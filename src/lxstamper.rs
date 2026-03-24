// Reticulum License
//
// Copyright (c) 2016-2025 Mark Qvist
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// - The Software shall not be used in any kind of system which includes amongst
//   its functions the ability to purposefully do harm to human beings.
//
// - The Software shall not be used, directly or indirectly, in the creation of
//   an artificial intelligence, machine learning or language model training
//   dataset, including but not limited to any use that contributes to the
//   training or development of such a model or algorithm.
//
// - The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use sha2::{Digest, Sha256};

/// LXMF-style proof-of-work stamp generator and validator
/// This is a minimal implementation compatible with LXMF stamps
pub struct LXStamper;

impl LXStamper {
    pub const STAMP_SIZE: usize = 32;
    
    /// Generate a workblock from the given data
    /// The workblock is used as the basis for stamp validation
    pub fn stamp_workblock(data: &[u8], expand_rounds: u32) -> Vec<u8> {
        let mut workblock = crate::identity::full_hash(data);
        
        // Expand the workblock through multiple hash rounds
        for _ in 0..expand_rounds {
            workblock = crate::identity::full_hash(&workblock);
        }
        
        workblock
    }
    
    /// Generate a proof-of-work stamp
    /// Returns (stamp, value) where value indicates the computational cost
    pub fn generate_stamp(data: &[u8], stamp_cost: u32, expand_rounds: u32) -> (Vec<u8>, u32) {
        let workblock = Self::stamp_workblock(data, expand_rounds);
        
        // Simple proof-of-work: find a nonce that produces a hash with enough leading zeros
        let mut nonce = 0u128;
        let target = stamp_cost;
        
        loop {
            let stamp = Self::compute_stamp(&workblock, nonce);
            let value = Self::stamp_value(&workblock, &stamp);
            
            if value >= target {
                return (stamp, value);
            }
            
            nonce += 1;
            
            // Prevent infinite loops by capping iterations
            if nonce > 1_000_000 {
                // Return whatever we have so far
                return (stamp, value);
            }
        }
    }
    
    /// Compute a stamp from workblock and nonce
    fn compute_stamp(workblock: &[u8], nonce: u128) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(workblock);
        hasher.update(nonce.to_le_bytes());
        hasher.finalize().to_vec()
    }
    
    /// Calculate the value (difficulty) of a stamp
    pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
        if stamp.len() < Self::STAMP_SIZE {
            return 0;
        }
        
        // Calculate proof-of-work difficulty by counting leading zeros
        let mut hasher = Sha256::new();
        hasher.update(workblock);
        hasher.update(stamp);
        let result = hasher.finalize();
        
        // Count leading zero bits
        let mut value = 0u32;
        for byte in result.iter() {
            if *byte == 0 {
                value += 8;
            } else {
                value += byte.leading_zeros();
                break;
            }
        }
        
        value
    }
    
    /// Validate a stamp against required value and workblock
    pub fn stamp_valid(stamp: &[u8], required_value: u32, workblock: &[u8]) -> bool {
        if stamp.len() < Self::STAMP_SIZE {
            return false;
        }
        
        let value = Self::stamp_value(workblock, stamp);
        value >= required_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stamp_generation() {
        let data = b"test data";
        let (stamp, value) = LXStamper::generate_stamp(data, 8, 2);
        
        assert!(stamp.len() >= LXStamper::STAMP_SIZE);
        assert!(value >= 8);
    }
    
    #[test]
    fn test_stamp_validation() {
        let data = b"test data";
        let (stamp, _value) = LXStamper::generate_stamp(data, 8, 2);
        let workblock = LXStamper::stamp_workblock(data, 2);
        
        assert!(LXStamper::stamp_valid(&stamp, 8, &workblock));
        assert!(!LXStamper::stamp_valid(&stamp, 100, &workblock)); // Too high requirement
    }
    
    #[test]
    fn test_stamp_value() {
        // Generate a real stamp and verify stamp_value agrees with it
        let data = b"test value data";
        let required = 8u32;
        let (stamp, _) = LXStamper::generate_stamp(data, required, 2);
        let workblock = LXStamper::stamp_workblock(data, 2);

        let value = LXStamper::stamp_value(&workblock, &stamp);
        // A properly generated stamp must satisfy the required difficulty
        assert!(value >= required, "stamp_value {} should be >= {}", value, required);
    }
}
