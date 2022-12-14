use crate::trie::VerkleError::{NotSupportedNodeType, SerializedPayloadTooShort};
use ark_ff::fields::PrimeField;
use banderwagon::{Element, Fr};
use num_traits::identities::One;
use num_traits::identities::Zero;
use std::any::Any;
use std::ptr::NonNull;
use ark_ff::BigInteger;
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

fn fill_suffix_tree_poly(poly: &mut [Fr], val: &[Option<[u8; 32]>]) -> usize {
    let mut count = 0;
    val.into_iter().enumerate().for_each(|(i, v)| {
        if let Some(value) = v {
            count += 1;
            leaf_to_comms(&mut poly[((i << 1) & 0xFF) as usize..], value);
        }
    });

    count
}

fn to_fr(p: &Element) -> Fr {
    Fr::from_le_bytes_mod_order(p.map_to_field().0.to_bytes_le().as_slice())
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
    fn commit_to_poly(&self, evaluations: &[Fr], count: usize) -> Element;
}

pub trait Deserializer {}

pub trait VerkleTrie {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()>;

    fn get(&self, key: Key) -> VerkleResult<Option<Value>>;

    fn compute_commitment(&mut self, committer: &dyn Committer) -> Element;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn serialize(&self, committer: &dyn Committer) -> VerkleResult<Vec<u8>>;
}

pub struct NodeHeader {
    commitment: Option<Element>,
    hash_commitment: Option<Fr>,
}

pub struct LeafNode {
    header: NodeHeader,
    stem: [u8; 31],
    values: [Option<[u8; 32]>; NODE_WIDTH],
    c1: Option<Element>,
    c2: Option<Element>,
    depth: u8,
}

pub struct InternalNode {
    children: [Option<NonNull<dyn VerkleTrie>>; NODE_WIDTH],
    header: NodeHeader,
    depth: u8,
}

impl VerkleTrie for InternalNode {
    fn put(&mut self, key: Key, value: Value) -> VerkleResult<()> {
        todo!()
    }

    fn get(&self, key: Key) -> VerkleResult<Option<Value>> {
        todo!()
    }

    fn compute_commitment(&mut self, committer: &dyn Committer) -> Element {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn serialize(&self, committer: &dyn Committer) -> VerkleResult<Vec<u8>> {
        let mut bitlist = [0u8; 32];
        let mut children = Vec::with_capacity(NODE_WIDTH * 32);
        self.children.iter().enumerate().for_each(|(i, c)| {
            unsafe {
                if c.is_some() {
                    set_bit(&mut bitlist, i);
                    let digits = c.unwrap().as_mut().compute_commitment(committer).to_bytes();
                    children.extend_from_slice(&digits);
                }
            }
        });

        let mut res = Vec::new();
        res.push(INTERNAL_FLAG);
        res.extend_from_slice(&bitlist);
        res.extend(children);

        Ok(res)
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
            header: NodeHeader { commitment: None, hash_commitment: None },
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
                    header: NodeHeader { commitment: None, hash_commitment: None },
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
                                header: NodeHeader { commitment: None, hash_commitment: None },
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

    fn compute_commitment(&mut self, committer: &dyn Committer) -> Element {
        let mut count;
        let mut poly: [Fr; 256] = [Fr::zero(); 256];
        poly[0] = Fr::one();
        poly[1] = Fr::from_le_bytes_mod_order(&self.stem);

        let mut c1_poly: [Fr; 256] = [Fr::zero(); 256];
        count = fill_suffix_tree_poly(&mut c1_poly, &self.values[..128]);
        let c1 = committer.commit_to_poly(&c1_poly, 256 - count);
        poly[2] = to_fr(&c1);
        self.c1 = Some(c1);

        let mut c2_poly: [Fr; 256] = [Fr::zero(); 256];
        count = fill_suffix_tree_poly(&mut c2_poly, &self.values[128..]);
        let c2 = committer.commit_to_poly(&c2_poly, 256 - count);
        poly[3] = to_fr(&c2);
        self.c1 = Some(c2);

        committer.commit_to_poly(&poly, 252)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn serialize(&self, committer: &dyn Committer) -> VerkleResult<Vec<u8>> {
        let mut bitlist = [0u8; 32];
        let mut children = Vec::with_capacity(NODE_WIDTH * 32);
        self.values.iter().enumerate().for_each(|(i, v)| {
            unsafe {
                if v.is_some() {
                    set_bit(&mut bitlist, i);
                    children.extend_from_slice(&v.unwrap());
                }
            }
        });

        let mut res = Vec::new();
        res.push(LEAF_FLAG);
        res.extend_from_slice(&self.stem);
        res.extend_from_slice(&bitlist);
        res.extend(children);

        Ok(res)
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
    use std::fs::File;
    use std::ops::Deref;
    use std::sync::{Arc, LazyLock, Mutex};
    use banderwagon::{Element, Fr};
    use num_traits::{One, Zero};
    use crate::precompute::{CRS, PrecomputeLagrange};
    use crate::trie::{InternalNode, Key, LeafNode, Value, NODE_WIDTH, leaf_to_comms, VerkleTrie, NodeHeader};
    use crate::trie::Committer;

    static COMMITTER: LazyLock<PrecomputeLagrange> = LazyLock::new(|| PrecomputeLagrange::precompute(&CRS.G));

    #[test]
    fn test_set_child() {
        let mut internal_node = InternalNode::new(1);
        let res = internal_node.set_child(NODE_WIDTH - 1, None);
        let msg = format!("{:}", res.unwrap_err());
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

    #[test]
    fn test_leaf_node_commitment() {
        use ark_serialize::CanonicalSerialize;
        let serialized = [0u8; 32];
        let mut values: [Option<[u8; 32]>; NODE_WIDTH] = [None; NODE_WIDTH];
        values[1] = Some([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
        let mut leaf_node = LeafNode {
            header: NodeHeader { commitment: None, hash_commitment: None },
            stem: serialized[..31].try_into().unwrap(),
            values,
            c1: None,
            c2: None,
            depth: 1,
        };

        // let mut file = File::create("precomp1").unwrap();
        let committer1 = PrecomputeLagrange::precompute(&CRS.G);
        // committer1.serialize_unchecked(&mut file).unwrap();

        let a = leaf_node.compute_commitment(&committer1);
        println!("{:?}", a);
    }
}
