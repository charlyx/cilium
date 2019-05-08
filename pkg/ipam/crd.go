// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipam

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/trigger"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	sharedNodeStore *nodeStore
	initNodeStore   sync.Once
)

type nodeStore struct {
	mutex          lock.RWMutex
	ownNode        *ciliumv2.CiliumNode
	allocators     []*crdAllocator
	refreshTrigger *trigger.Trigger
	availableIPs   map[Family]int
}

func newNodeStore() *nodeStore {
	log.Infof("Subscribed to CiliumNode custom resource for node %s", node.GetName())
	store := &nodeStore{
		allocators:   []*crdAllocator{},
		availableIPs: map[Family]int{},
	}
	ciliumClient := k8s.CiliumClient()

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "crd-allocator-node-refresher",
		MinInterval: 15 * time.Second,
		TriggerFunc: store.refreshNodeTrigger,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize trigger")
	}
	store.refreshTrigger = t

	//ciliumNodeSelector := fields.ParseSelectorOrDie("metadata.name=" + node.GetName())
	ciliumNodeStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					log.Infof("New CiliumNode %+v", node)
					store.updateNodeResource(node)
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node, ok := newObj.(*ciliumv2.CiliumNode); ok {
					log.Debugf("Updated CiliumNode %+v", node)
					store.updateNodeResource(node)
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node, ok := obj.(*ciliumv2.CiliumNode); ok {
					log.Debugf("Deleted CiliumNode %+v", node)
					store.updateNodeResource(nil)
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", obj)
				}
			},
		},
		func(obj interface{}) interface{} {
			cnp, _ := obj.(*ciliumv2.CiliumNode)
			return cnp
		},
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	log.Infof("Waiting for CiliumNode custom resource %s to synchronize...", node.GetName())
	if ok := cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced); !ok {
		log.Fatalf("Unable to synchronize CiliumNode custom resource for node %s", node.GetName())
	} else {
		log.Infof("Successfully synchronized CiliumNode custom resource for node %s", node.GetName())
	}

	return store
}

func (n *nodeStore) updateNodeResource(node *ciliumv2.CiliumNode) {
	n.mutex.Lock()
	if node != nil {
		n.ownNode = node.DeepCopy()
		n.availableIPs[IPv4] = 0
		n.availableIPs[IPv6] = 0
		if node.Spec.IPAM.Available != nil {
			for ipString := range node.Spec.IPAM.Available {
				if ip := net.ParseIP(ipString); ip != nil {
					if ip.To4() != nil {
						n.availableIPs[IPv4]++
					} else {
						n.availableIPs[IPv6]++
					}
				}
			}
		}
	} else {
		n.ownNode = nil
	}
	n.mutex.Unlock()
}

func (n *nodeStore) refreshNodeTrigger(reasons []string) {
	if err := n.refreshNode(); err != nil {
		log.WithError(err).Warning("Unable to update CiliumNode custom resource")
		// Trigger another run in the interval
		n.refreshTrigger.Trigger()
	}
}

func (n *nodeStore) refreshNode() error {
	n.mutex.RLock()
	if n.ownNode == nil {
		n.mutex.RUnlock()
		return nil
	}
	node := n.ownNode.DeepCopy()
	staleCopyOfAllocators := make([]*crdAllocator, len(n.allocators))
	copy(staleCopyOfAllocators, n.allocators)
	n.mutex.RUnlock()

	node.Status.IPAM.InUse = map[string]ciliumv2.AllocationIP{}

	for _, a := range staleCopyOfAllocators {
		a.mutex.RLock()
		for ip, ipInfo := range a.allocated {
			node.Status.IPAM.InUse[ip] = ipInfo
		}
		a.mutex.RUnlock()
	}

	var err error
	k8sCapabilities := k8sversion.Capabilities()
	ciliumClient := k8s.CiliumClient()
	switch {
	case k8sCapabilities.UpdateStatus:
		_, err = ciliumClient.CiliumV2().CiliumNodes("default").UpdateStatus(node)
	default:
		_, err = ciliumClient.CiliumV2().CiliumNodes("default").Update(node)
	}

	return err
}

func (n *nodeStore) allocate(ip net.IP) (*ciliumv2.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	if n.ownNode.Spec.IPAM.Available == nil {
		return nil, fmt.Errorf("No IPs available")
	}

	ipInfo, ok := n.ownNode.Spec.IPAM.Available[ip.String()]
	if !ok {
		return nil, fmt.Errorf("IP %s is not available", ip.String())
	}

	return &ipInfo, nil
}

func (n *nodeStore) allocateNext(allocated map[string]ciliumv2.AllocationIP, family Family) (net.IP, *ciliumv2.AllocationIP, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.ownNode == nil {
		return nil, nil, fmt.Errorf("CiliumNode for own node is not available")
	}

	for ip, ipInfo := range n.ownNode.Spec.IPAM.Available {
		if _, ok := allocated[ip]; !ok {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				log.Warning("Unable to parse IP %s in CiliumNode %s", ip, n.ownNode.Name)
				continue
			}

			if DeriveFamily(parsedIP) != family {
				continue
			}

			return parsedIP, &ipInfo, nil
		}
	}

	return nil, nil, fmt.Errorf("No more IPs available")
}

func (n *nodeStore) numAvailableIPs() int {
	if n.ownNode != nil {
		return len(n.ownNode.Spec.IPAM.Available)
	}
	return 0
}

type crdAllocator struct {
	store     *nodeStore
	mutex     lock.RWMutex
	allocated map[string]ciliumv2.AllocationIP
	family    Family
}

func newCRDAllocator(family Family) Allocator {
	initNodeStore.Do(func() {
		sharedNodeStore = newNodeStore()
	})

	allocator := &crdAllocator{
		allocated: map[string]ciliumv2.AllocationIP{},
		family:    family,
		store:     sharedNodeStore,
	}

	sharedNodeStore.mutex.Lock()
	sharedNodeStore.allocators = append(sharedNodeStore.allocators, allocator)
	sharedNodeStore.mutex.Unlock()

	return allocator
}

func (a *crdAllocator) Allocate(ip net.IP, owner string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; ok {
		return fmt.Errorf("IP already in use")
	}

	ipInfo, err := a.store.allocate(ip)
	if err != nil {
		return err
	}

	a.markAllocated(ip, owner, *ipInfo)

	return nil
}

func (a *crdAllocator) Release(ip net.IP) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.allocated[ip.String()]; !ok {
		return fmt.Errorf("IP %s is not allocated", ip.String())
	}

	delete(a.allocated, ip.String())
	a.store.refreshTrigger.Trigger()

	return nil
}

func (a *crdAllocator) markAllocated(ip net.IP, owner string, ipInfo ciliumv2.AllocationIP) {
	ipInfo.Owner = owner
	a.allocated[ip.String()] = ipInfo
	a.store.refreshTrigger.Trigger()
}

func (a *crdAllocator) AllocateNext(owner string) (net.IP, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	ip, ipInfo, err := a.store.allocateNext(a.allocated, a.family)
	if err != nil {
		return nil, err
	}

	a.markAllocated(ip, owner, *ipInfo)

	return ip, nil
}

func (a *crdAllocator) totalAvailableIPs() int {
	if num, ok := a.store.availableIPs[a.family]; ok {
		return num
	}
	return 0
}

func (a *crdAllocator) Dump() (map[string]string, string) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	allocs := map[string]string{}
	for ip := range a.allocated {
		allocs[ip] = ""
	}

	status := fmt.Sprintf("%d/%d allocated", len(allocs), a.totalAvailableIPs())
	return allocs, status
}
