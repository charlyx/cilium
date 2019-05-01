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
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var ciliumNodeStore cache.Store

func convertToCiliumNode(obj interface{}) interface{} {
	cnp, _ := obj.(*v2.CiliumNode)
	return cnp
}

func startSynchronizingCiliumNodes() {
	log.Info("Starting to synchronize CiliumNode custom resources...")

	ciliumNodeStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, fields.Everything()),
		&v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node, ok := obj.(*v2.CiliumNode); ok {
					log.Debugf("New CiliumNode %+v", node)
					ciliumNodes.Update(node)
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node, ok := newObj.(*v2.CiliumNode); ok {
					log.Debugf("Updated CiliumNode %+v", node)
					ciliumNodes.Update(node)
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node, ok := obj.(*v2.CiliumNode); ok {
					log.Debugf("Deleted CiliumNode %+v", node)
					ciliumNodes.Delete(node.Name)
				} else {
					log.Warning("Unknown CiliumNode object received: %+v", obj)
				}
			},
		},
		convertToCiliumNode,
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	startENIAllocator()
}
