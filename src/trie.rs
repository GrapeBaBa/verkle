use crate::trie::VerkleError::NotSupportedNodeType;
use banderwagon::{Element, Fr};
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::rc::Rc;
use thiserror::Error;

pub type Key = [u8; 32];
pub type Value = [u8; 32];

const NODE_WIDTH: usize = 256;

#[derive(Error, Debug)]
pub enum VerkleError {
    #[error("child index {0} higher than node width (expected < {})", NODE_WIDTH - 1)]
    ChildIndexTooLarge(usize),

    #[error("key stem '{0:?}' not match node stem '{1:?}'")]
    StemNotMatch([u8; 31], [u8; 31]),

    #[error("not supported node type")]
    NotSupportedNodeType,
}

pub type VerkleResult<T> = Result<T, VerkleError>;

pub trait Committer {
    fn commit_to_poly(&self, evaluations: &[Fr]) -> Element;
}

pub trait VerkleTrie {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()>;

    fn get(&self, key: Key) -> VerkleResult<Option<Value>>;

    fn compute_commitment(&self) -> Element;

    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct LeafNode {
    stem: [u8; 31],
    values: [Option<[u8; 32]>; NODE_WIDTH],
    c1: Option<Element>,
    c2: Option<Element>,
    depth: u8,
}

pub struct InternalNode {
    children: [Option<NonNull<dyn VerkleTrie>>; NODE_WIDTH],
    depth: u8,
}

impl VerkleTrie for InternalNode {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()> {
        todo!()
    }

    fn get(&self, key: Key) -> VerkleResult<Option<Value>> {
        todo!()
    }

    fn compute_commitment(&self) -> Element {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub enum VerkleTrieNode {
    Leaf(LeafNode),
    Internal(InternalNode),
}

impl InternalNode {
    pub fn new(depth: u8) -> Self {
        Self {
            children: [None; NODE_WIDTH],
            depth,
        }
    }

    pub fn children(&self) -> &[Option<NonNull<dyn VerkleTrie>>; NODE_WIDTH] {
        &self.children
    }

    pub fn set_child(
        &mut self,
        index: usize,
        child: Option<NonNull<dyn VerkleTrie>>,
    ) -> VerkleResult<()> {
        if index >= NODE_WIDTH - 1 {
            return Err(VerkleError::ChildIndexTooLarge(index));
        }

        self.children[index] = child;
        Ok(())
    }

    pub fn insert(&mut self, key: Key, value: Value) -> VerkleResult<()> {
        let n_child = key[self.depth as usize];
        let child = self.children[n_child as usize];
        match child {
            None => {
                let mut leaf_node = LeafNode {
                    stem: key[..31].try_into().unwrap(),
                    values: [None; NODE_WIDTH],
                    c1: None,
                    c2: None,
                    depth: self.depth + 1,
                };
                leaf_node.values[key[31] as usize] = Some(value);
                self.children[n_child as usize] = NonNull::new(&mut leaf_node as *mut _);
                Ok(())
            }
            Some(mut node) => unsafe {
                if let Some(cur_leaf_node) = node.as_mut().as_any_mut().downcast_mut::<LeafNode>() {
                    if cur_leaf_node.stem == key[..31] {
                        return cur_leaf_node.insert(key, value);
                    } else {
                        let next_char_in_current_leaf =
                            cur_leaf_node.stem[(self.depth + 1) as usize];
                        let mut branch = InternalNode::new(self.depth + 1);
                        cur_leaf_node.depth += 1;
                        branch.children[next_char_in_current_leaf as usize] =
                            Some(NonNull::from(cur_leaf_node));
                        self.children[n_child as usize] = NonNull::new(&mut branch as *mut _);

                        let next_char_in_inserted_key = key[(self.depth + 1) as usize];
                        if next_char_in_current_leaf != next_char_in_inserted_key {
                            let mut new_leaf_node = LeafNode {
                                stem: key[..31].try_into().unwrap(),
                                values: [None; NODE_WIDTH],
                                c1: None,
                                c2: None,
                                depth: self.depth + 2,
                            };
                            new_leaf_node.values[key[31] as usize] = Some(value);
                            branch.children[next_char_in_inserted_key as usize] =
                                NonNull::new(&mut new_leaf_node as *mut _);
                            return Ok(());
                        } else {
                            return branch.insert(key, value);
                        }
                    }
                };

                if let Some(cur_internal_node) =
                node.as_mut().as_any_mut().downcast_mut::<InternalNode>()
                {
                    return cur_internal_node.insert(key, value);
                }

                Err(NotSupportedNodeType)
            },
        }
    }
}

impl VerkleTrie for LeafNode {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()> {
        todo!()
    }

    fn get(&self, key: Key) -> VerkleResult<Option<Value>> {
        todo!()
    }

    fn compute_commitment(&self) -> Element {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl LeafNode {
    pub fn insert(&mut self, key: Key, value: Value) -> VerkleResult<()> {
        if key[..31] != self.stem {
            return Err(VerkleError::StemNotMatch(
                key[..31].try_into().unwrap(),
                self.stem,
            ));
        }

        self.values[key[31] as usize] = Some(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::trie::{InternalNode, Key, LeafNode, Value, NODE_WIDTH};

    #[test]
    fn test_set_child() {
        let mut internal_node = InternalNode::new(1);
        let res = internal_node.set_child(NODE_WIDTH - 1, None);
        let msg = format!("{}", res.unwrap_err());
        assert_eq!(
            "child index 255 higher than node width (expected < 255)",
            msg
        );
    }

    #[test]
    fn test_internal_node_insert() {
        let mut internal_node = InternalNode::new(1);
        let key: Key = [0u8; 32];
        let value: Value = [1u8; 32];
        internal_node.insert(key, value);
        assert!(internal_node.children[0].is_some());
        let value1: Value = [2u8; 32];
        internal_node.insert(key, value1);
        assert!(internal_node.children[0].is_some());
        let leaf_node = unsafe { internal_node.children[0].unwrap().as_mut() }
            .as_any_mut()
            .downcast_mut::<LeafNode>()
            .unwrap();
        assert_eq!(value1, leaf_node.values[0].unwrap());
    }
}
