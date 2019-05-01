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

package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	lyftaws "github.com/lyft/cni-ipvlan-vpc-k8s/aws"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

const (
	defaultPreAllocation = 4
)

var (
	awsSession        *session.Session
	ec2Client         ec2iface.EC2API
	metadataClient    *ec2metadata.EC2Metadata
	identityDocument  *ec2metadata.EC2InstanceIdentityDocument
	allocationTrigger *trigger.Trigger
)

type instance struct {
	enis map[string]*v2.ENI
}

type instanceMap map[string]*instance

func (m instanceMap) add(eni *v2.ENI) {
	i, ok := m[eni.InstanceID]
	if !ok {
		i = &instance{}
		m[eni.InstanceID] = i
	}

	if i.enis == nil {
		i.enis = map[string]*v2.ENI{}
	}

	i.enis[eni.ID] = eni
}

type instancesManager struct {
	mutex     lock.RWMutex
	instances instanceMap
}

func (m *instancesManager) updateENI(eni *v2.ENI) {
	m.mutex.Lock()
	m.instances.add(eni)
	m.mutex.Unlock()
}

func (m *instancesManager) Resync() {
	instances, err := getInstanceInterfaces()
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 interface list")
		return
	}

	m.mutex.Lock()
	m.instances = instances
	m.mutex.Unlock()
}

func (m *instancesManager) getENIs(instanceID string) []*v2.ENI {
	enis := []*v2.ENI{}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if i, ok := m.instances[instanceID]; ok {
		for _, e := range i.enis {
			enis = append(enis, e.DeepCopy())
		}
	}

	return enis
}

var instances = instancesManager{instances: instanceMap{}}

type ciliumNode struct {
	name            string
	neededAddresses int
	resource        *v2.CiliumNode
}

type ciliumNodeMap map[string]*ciliumNode

type nodeManager struct {
	mutex lock.RWMutex
	nodes ciliumNodeMap
}

var ciliumNodes = nodeManager{nodes: ciliumNodeMap{}}

func (n *ciliumNode) Allocate() {
	//	var alloc *aws.AllocationResult
	//	registry := &aws.Registry{}
	//	free, err := aws.FindFreeIPsAtIndex(node.Spec.ENI.FirstAllocationInterface, true)
	//	if err == nil && len(free) > 0 {
	//		registryFreeIPs, err := registry.TrackedBefore(time.Now().Add(time.Duration(-3600) * time.Second))
	//		if err == nil && len(registryFreeIPs) > 0 {
	//		loop:
	//			for _, freeAlloc := range free {
	//				for _, freeRegistry := range registryFreeIPs {
	//					if freeAlloc.IP.Equal(freeRegistry) {
	//						alloc = freeAlloc
	//						// update timestamp
	//						registry.TrackIP(freeRegistry)
	//						break loop
	//					}
	//				}
	//			}
	//		}
	//	}
	//
	//	if alloc == nil {
	// allocate an IP on an available interface
	var newInterface *lyftaws.Interface
	result, err := lyftaws.DefaultClient.AllocateIPFirstAvailableAtIndex(n.resource.Spec.ENI.FirstAllocationInterface)
	if err != nil {
		newInterface, err = lyftaws.DefaultClient.NewInterface(n.resource.Spec.ENI.SecurityGroups, n.resource.Spec.ENI.SubnetTags)
		if err != nil {
			log.WithError(err).Warning("Unable to allocate ENI")
			return
		}
	} else {
		newInterface = &result.Interface
	}

	eni := v2.ENI{
		ID:            newInterface.ID,
		MAC:           newInterface.Mac,
		InterfaceName: newInterface.IfName,
		Number:        newInterface.Number,
		Addresses:     []string{},
		Subnet: v2.AwsSubnet{
			ID: newInterface.SubnetID,
		},
		VPC: v2.AwsVPC{
			ID:    newInterface.VpcID,
			CIDRs: []string{},
		},
		SecurityGroups: newInterface.SecurityGroupIds,
	}

	if newInterface.SubnetCidr != nil {
		eni.Subnet.CIDR = newInterface.SubnetCidr.String()
	}

	if newInterface.VpcPrimaryCidr != nil {
		eni.VPC.PrimaryCIDR = newInterface.VpcPrimaryCidr.String()
	}

	for _, ip := range newInterface.VpcCidrs {
		eni.VPC.CIDRs = append(eni.VPC.CIDRs, ip.String())
	}

	for _, ip := range newInterface.IPv4s {
		eni.Addresses = append(eni.Addresses, ip.String())
	}

	instances.updateENI(&eni)
}

func (n *ciliumNode) refresh() error {
	node := n.resource.DeepCopy()

	if node.Spec.IPAM.Available == nil {
		node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	}

	if node.Status.IPAM.InUse == nil {
		node.Status.IPAM.InUse = map[string]v2.AllocationIP{}
	}

	relevantENIs := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	node.Status.ENI.ENIs = map[string]v2.ENI{}
	node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	for _, e := range relevantENIs {
		node.Status.ENI.ENIs[e.ID] = *e

		if e.Number < node.Spec.ENI.FirstAllocationInterface {
			log.Debugf("Ignoring ENI %s (index %d < %d)", e.ID, e.Number, node.Spec.ENI.FirstAllocationInterface)
			continue
		}

		for _, ip := range e.Addresses {
			node.Spec.IPAM.Available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}

	_, err := ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
	return err
}

func (n *nodeManager) Update(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &ciliumNode{
			name: resource.Name,
		}
		n.nodes[node.name] = node
	}
	node.resource = resource

	requiredAddresses := resource.Spec.ENI.PreAllocate
	if requiredAddresses == 0 {
		requiredAddresses = defaultPreAllocation
	}

	availableIPs := len(resource.Spec.IPAM.Available)
	usedIPs := len(resource.Status.IPAM.InUse)
	node.neededAddresses = requiredAddresses - (availableIPs - usedIPs)

	log.WithFields(logrus.Fields{
		"instanceID":      resource.Spec.ENI.InstanceID,
		"addressesNeeded": node.neededAddresses,
	}).Infof("Updated node %s", resource.Name)
}

func (n *nodeManager) Delete(nodeName string) {
	n.mutex.Lock()
	delete(n.nodes, nodeName)
	n.mutex.Unlock()
}

func (n *nodeManager) AllocateForNode(nodeName string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	node, ok := n.nodes[nodeName]
	if ok {
		node.Allocate()
	}
}

func (n *nodeManager) Refresh() {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, node := range n.nodes {
		if err := node.refresh(); err != nil {
			log.WithError(err).Warning("Refreshing CiliumNode resource failed")
		}
	}
}

//type subnet struct {
//	ID                    string
//	Cidr                  string
//	IsDefault             bool
//	AvailableAddressCount int
//	Name                  string
//	Tags                  map[string]string
//}
//
//func getCachedSubnets() (subnets []subnet, err error) {
//	state := awscache.Get("subnets_for_instance", &subnets)
//	if state == awscache.CacheFound {
//		return
//	}
//	subnets, err = getSubnets()
//	if err == nil {
//		cache.Store("subnets", time.Minute, &subnets)
//	}
//	return
//}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}
	return filter
}

//func getSubnets() ([]subnet, error) {
//	var subnets []subnet
//
//	az := identityDocument.AvailabilityZone
//
//	// getting all interfaces attached to this specific machine so we can
//	// find out what is our vpc-id interfaces[0] is going to be our eth0,
//	// interfaces slice gets sorted by number before returning to the
//	// caller
//	interfaces, err := getInterfaces()
//	if err != nil {
//		return nil, fmt.Errorf("failed to get interfaces: %s", err)
//	}
//
//	result, err := ec2Client.DescribeSubnets(&ec2.DescribeSubnetsInput{
//		Filters: []*ec2.Filter{
//			newEc2Filter("vpc-id", interfaces[0].VPC.ID),
//			newEc2Filter("availabilityZone", az),
//		},
//	})
//
//	if err != nil {
//		return nil, err
//	}
//
//	for _, awsSub := range result.Subnets {
//		subnet := subnet{
//			ID:                    *awsSub.SubnetId,
//			Cidr:                  *awsSub.CidrBlock,
//			IsDefault:             *awsSub.DefaultForAz,
//			AvailableAddressCount: int(*awsSub.AvailableIpAddressCount),
//			Tags:                  map[string]string{},
//		}
//		// Set all the tags on the result
//		for _, tag := range awsSub.Tags {
//			if *tag.Key == "Name" {
//				subnet.Name = *tag.Value
//			} else {
//				subnet.Tags[*tag.Key] = *tag.Value
//			}
//		}
//		subnets = append(subnets, subnet)
//	}
//
//	return subnets, nil
//}

func convertToENI(iface *ec2.NetworkInterface) (v2.ENI, error) {
	if iface.PrivateIpAddress == nil {
		return v2.ENI{}, fmt.Errorf("ENI has no IP address")
	}

	eni := v2.ENI{
		IP:             *iface.PrivateIpAddress,
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.MacAddress != nil {
		eni.MAC = *iface.MacAddress
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = *iface.NetworkInterfaceId
	}

	if iface.Description != nil {
		eni.Description = *iface.Description
	}

	if iface.Attachment != nil {
		if iface.Attachment.DeviceIndex != nil {
			eni.Number = int(*iface.Attachment.DeviceIndex)
		}

		if iface.Attachment.InstanceId != nil {
			eni.InstanceID = *iface.Attachment.InstanceId
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = *iface.SubnetId
	}

	if iface.VpcId != nil {
		eni.VPC.ID = *iface.VpcId
	}

	for _, ip := range iface.PrivateIpAddresses {
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, *ip.PrivateIpAddress)
		}
	}

	//	for _, ip := range iface.Ipv6Addresses {
	//		if ip.Ipv6Address {
	//			eni.Addresses = append(eni.Addresses, *ip.Ipv6Address)
	//		}
	//	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, *g.GroupId)
		}
	}

	return eni, nil
}

func getInstanceInterfaces() (instanceMap, error) {
	instances := instanceMap{}

	req := ec2.DescribeNetworkInterfacesInput{}
	response, err := ec2Client.DescribeNetworkInterfaces(&req)
	if err != nil {
		return nil, err
	}

	for _, iface := range response.NetworkInterfaces {
		eni, err := convertToENI(iface)
		if err != nil {
			log.WithError(err).Warning("Unable to convert NetworkInterface to internal representation")
		} else {
			log.Infof("instance %s - eni %s", eni.InstanceID, eni.ID)
			instances.add(&eni)
		}
	}

	return instances, nil
}

func jitter(d time.Duration, pct float64) time.Duration {
	jitter := rand.Int63n(int64(float64(d) * pct))
	d += time.Duration(jitter)
	return d
}

func eniGC() error {
	reg := &lyftaws.Registry{}
	freeAfter := time.Minute
	// Insert free-after jitter of 15% of the period
	freeAfter = jitter(freeAfter, 0.15)

	// Invert free-after
	freeAfter *= -1

	ips, err := reg.TrackedBefore(time.Now().Add(freeAfter))
	if err != nil {
		return err
	}

	for _, ip := range ips {
		err := lyftaws.DefaultClient.DeallocateIP(&ip)
		if err == nil {
			reg.ForgetIP(ip)
			log.Info("Released IP %s for use", ip)
		} else {
			log.WithError(err).Warning("Cannot deallocate %s", ip)
		}
	}

	return nil
}

func convertToPod(obj interface{}) interface{} {
	pod, _ := obj.(*v1.Pod)
	return pod
}

func allocateTrigger(reasons []string) {
	for _, nodeName := range reasons {
		ciliumNodes.AllocateForNode(nodeName)
	}
}

func startENIAllocator() error {
	log.Info("Starting ENI allocator...")

	awsSession = session.Must(session.NewSession())
	metadataClient = ec2metadata.New(awsSession)

	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	allocationTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-allocation",
		MinInterval: 5 * time.Second,
		TriggerFunc: allocateTrigger,
	})
	if err != nil {
		return fmt.Errorf("unable to initialize trigger: %s", err)
	}

	identityDocument = &instance
	ec2Client = ec2.New(awsSession, aws.NewConfig().WithRegion(identityDocument.Region))

	instances.Resync()

	log.Info("Starting ENI operator...")
	mngr := controller.NewManager()
	mngr.UpdateController("refresh-cilium-nodes",
		controller.ControllerParams{
			RunInterval: 5 * time.Second,
			DoFunc: func(_ context.Context) error {
				log.Debugf("Refreshing CiliumNode resources...")
				ciliumNodes.Refresh()
				return nil
			},
		})

	mngr.UpdateController("resync-interfaces",
		controller.ControllerParams{
			RunInterval: time.Minute,
			DoFunc: func(_ context.Context) error {
				log.Debugf("Resyncing interface list")
				instances.Resync()
				return nil
			},
		})
	//
	//	mngr.UpdateController("eni-gc",
	//		controller.ControllerParams{
	//			RunInterval: time.Minute,
	//			DoFunc: func(_ context.Context) error {
	//				log.Debugf("Running ENI garbage collector..")
	//				err := eniGC()
	//				if err != nil {
	//					log.WithError(err).Warning("ENI garbage collector failed")
	//				}
	//				return err
	//			},
	//		})

	return nil
}
