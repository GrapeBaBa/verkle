use crate::trie::VerkleError::{NotSupportedNodeType, SerializedPayloadTooShort};
use ark_ff::fields::PrimeField;
use banderwagon::{Element, Fr};
use num_traits::identities::One;
use num_traits::identities::Zero;
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
const MASK: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1];

fn bit(bit_list: &[u8], nr: usize) -> bool {
    if bit_list.len() * 8 <= nr {
        return false;
    }

    bit_list[nr / 8] & MASK[nr % 8] != 0
}

fn set_bit(bit_list: &mut [u8], index: usize) {
    bit_list[index / 8] |= MASK[index % 8]
}

fn leaf_to_comms(poly: &mut [Fr], val: &[u8]) {
    if val.len() == 0 {
        return;
    }

    if val.len() > 32 {
        panic!("invalid leaf length {}, {:?}", val.len(), val)
    }

    let mut val_lo_with_maker = [0u8; 17];
    let mut lo_end = 16;
    if val.len() < lo_end {
        lo_end = val.len();
    }

    val_lo_with_maker[..lo_end].copy_from_slice(&val[..lo_end]);
    val_lo_with_maker[16] = 1;
    poly[0] = from_le_bytes(&val_lo_with_maker);
    if val.len() >= 16 {
        poly[1] = from_le_bytes(&val[16..]);
    }
}

fn from_le_bytes(data: &[u8]) -> Fr {
    let mut aligned = [0u8; 32];
    aligned[..data.len()].copy_from_slice(data);
    Fr::from_le_bytes_mod_order(&aligned)
}

#[derive(Error, Debug)]
pub enum VerkleError {
    #[error("child index {0} higher than node width (expected < {})", NODE_WIDTH - 1)]
    ChildIndexTooLarge(usize),

    #[error("key stem '{0:?}' not match node stem '{1:?}'")]
    StemNotMatch([u8; 31], [u8; 31]),

    #[error("not supported node type")]
    NotSupportedNodeType,

    #[error("verkle payload is too short")]
    SerializedPayloadTooShort,
}

const LEAF_FLAG: u8 = 1;
const INTERNAL_FLAG: u8 = 2;

pub type VerkleResult<T> = Result<T, VerkleError>;

pub trait Committer {
    fn commit_to_poly(&self, evaluations: &[Fr]) -> Element;
}

pub trait Deserializer {}

pub trait VerkleTrie {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()>;

    fn get(&self, key: Key) -> VerkleResult<Option<Value>>;

    fn compute_commitment(&self, committer: &dyn Committer) -> Element;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn serialize(&self) -> VerkleResult<Vec<u8>>;
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

    fn compute_commitment(&self, committer: &dyn Committer) -> Element {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn serialize(&self) -> VerkleResult<Vec<u8>> {
        // let mut bitlist = [0u8; 32];
        // let mut children = Vec::with_capacity(NODE_WIDTH * 32);
        // self.children.iter().enumerate().for_each(|(i, c)| {
        //     if c.is_some() {
        //         set_bit(&bitlist, i);
        //     }
        // })
        // children: = make([]byte, 0, NodeWidth * 32)
        // for i, c: = range
        // n.children
        // {
        //     if _, ok: = c.(Empty);
        //     !ok {
        //         setBit(bitlist[: ],
        //         i)
        //         digits: = c.ComputeCommitment().Bytes()
        //         children = append(children,
        //         digits[: ]...)
        //     }
        // }
        // return append(append([]byte { internalRLPType }, bitlist[: ]...), children...);, nil
        todo!()
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

    pub fn deserialize(serialized: &[u8], depth: u8) -> VerkleResult<NonNull<dyn VerkleTrie>> {
        // if serialized.len() < 64 {
        //     return Err(SerializedPayloadTooShort);
        // }
        //
        // match serialized[0] {
        //     INTERNAL_FLAG => {}
        //     LEAF_FLAG => {}
        //     _ => {}
        // }
        Err(SerializedPayloadTooShort)
    }
}

impl VerkleTrie for LeafNode {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()> {
        todo!()
    }

    fn get(&self, key: Key) -> VerkleResult<Option<Value>> {
        todo!()
    }

    fn compute_commitment(&self, committer: &dyn Committer) -> Element {
        // let mut count = 0;
        // let mut poly: [Fr; 256] = [Fr::zero(); 256];
        // poly[0] = Fr::one();
        // poly[1] = Fr::from_le_bytes_mod_order(&self.stem);
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn serialize(&self) -> VerkleResult<Vec<u8>> {
        todo!()
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

    pub fn deserialize(serialized: &[u8], depth: u8) -> VerkleResult<NonNull<dyn VerkleTrie>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use banderwagon::Fr;
    use num_traits::{One, Zero};
    use crate::trie::{InternalNode, Key, LeafNode, Value, NODE_WIDTH, leaf_to_comms};

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

    #[test]
    fn test_leaf_to_comms_less_than_16() {
        let value = [0u8; 4];
        let mut p = [Fr::zero(); 2];
        leaf_to_comms(&mut p, &value);
        assert_eq!(3195623856215021945, p[0].0.0[0]);
        assert_eq!(6342950750355062753, p[0].0.0[1]);
        assert_eq!(18424290587888592554, p[0].0.0[2]);
        assert_eq!(1249884543737537366, p[0].0.0[3]);

        let value = [0u8; 15];
        let mut p = [Fr::zero(); 2];
        leaf_to_comms(&mut p, &value);
        assert_eq!(3195623856215021945, p[0].0.0[0]);
        assert_eq!(6342950750355062753, p[0].0.0[1]);
        assert_eq!(18424290587888592554, p[0].0.0[2]);
        assert_eq!(1249884543737537366, p[0].0.0[3]);
    }

    #[test]
    fn test_leaf_to_comms_less_than_32() {
        let value = [0u8; 16];
        let mut p = [Fr::zero(); 2];
        leaf_to_comms(&mut p, &value);
        assert_eq!(3195623856215021945, p[0].0.0[0]);
        assert_eq!(6342950750355062753, p[0].0.0[1]);
        assert_eq!(18424290587888592554, p[0].0.0[2]);
        assert_eq!(1249884543737537366, p[0].0.0[3]);

        assert_eq!(0, p[1].0.0[0]);
        assert_eq!(0, p[1].0.0[1]);
        assert_eq!(0, p[1].0.0[2]);
        assert_eq!(0, p[1].0.0[3]);

        let mut value1 = [0u8; 20];
        value1[17] = 1;
        value1[19] = 1;
        let mut p1 = [Fr::zero(); 2];
        leaf_to_comms(&mut p1, &value1);
        assert_eq!(3195623856215021945, p1[0].0.0[0]);
        assert_eq!(6342950750355062753, p1[0].0.0[1]);
        assert_eq!(18424290587888592554, p1[0].0.0[2]);
        assert_eq!(1249884543737537366, p1[0].0.0[3]);

        assert_eq!(6449575405170448856, p1[1].0.0[0]);
        assert_eq!(12539258271468081731, p1[1].0.0[1]);
        assert_eq!(4858174950920037973, p1[1].0.0[2]);
        assert_eq!(2041956332529055221, p1[1].0.0[3]);

        let mut value2 = [0u8; 32];
        value2[17] = 1;
        value2[19] = 1;
        let mut p2 = [Fr::zero(); 2];
        leaf_to_comms(&mut p2, &value2);
        assert_eq!(3195623856215021945, p2[0].0.0[0]);
        assert_eq!(6342950750355062753, p2[0].0.0[1]);
        assert_eq!(18424290587888592554, p2[0].0.0[2]);
        assert_eq!(1249884543737537366, p2[0].0.0[3]);

        assert_eq!(6449575405170448856, p2[1].0.0[0]);
        assert_eq!(12539258271468081731, p2[1].0.0[1]);
        assert_eq!(4858174950920037973, p2[1].0.0[2]);
        assert_eq!(2041956332529055221, p2[1].0.0[3]);
    }

    #[test]
    #[should_panic(expected = "invalid leaf length 33, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]")]
    fn test_leaf_to_comms_more_than_32() {
        let value = [0u8; 33];
        let mut p = [Fr::zero(); 2];
        leaf_to_comms(&mut p, &value);
    }
}
