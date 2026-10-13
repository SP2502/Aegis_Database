// Package benchindex is an experimental reversed-label map trie. It is used
// only to compare tradeoffs with the shipped sorted byte index.
package benchindex

import (
	"aegis-intelligence/pkg/dataset"
	"strings"
)

type Node struct {
	Children          map[string]*Node
	Exact, Subdomains uint16
}

func Build(entries []dataset.Entry) *Node {
	root := &Node{}
	for _, e := range entries {
		parts := strings.Split(e.Domain, ".")
		n := root
		for i := len(parts) - 1; i >= 0; i-- {
			if n.Children == nil {
				n.Children = map[string]*Node{}
			}
			child := n.Children[parts[i]]
			if child == nil {
				child = &Node{}
				n.Children[parts[i]] = child
			}
			n = child
		}
		n.Exact |= e.Exact
		n.Subdomains |= e.Subdomains
	}
	return root
}
func (n *Node) Lookup(s string) uint16 {
	var mask uint16
	end := len(s)
	for end > 0 {
		start := strings.LastIndexByte(s[:end], '.') + 1
		n = n.Children[s[start:end]]
		if n == nil {
			return mask
		}
		mask |= n.Subdomains
		if start == 0 {
			mask |= n.Exact
			break
		}
		end = start - 1
	}
	return mask
}
