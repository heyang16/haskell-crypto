module Crypto where

import Data.Char

import Prelude hiding (gcd)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

--Returns the greatest common divisor between m and n
gcd :: Int -> Int -> Int
gcd m n
  | n == 0 = m
  | otherwise = gcd n (m `mod` n)

--Returns the number of integers in the range 1 to x inclusive
--that are relatively prime to x
phi :: Int -> Int
phi x
  = length [y | y <- [2..(x+1)], gcd x y == 1]

-- Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a b
  = undefined

-- Inverse of a modulo m
inverse :: Int -> Int -> Int
inverse
  = undefined

-- Calculates (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a k m
  | k == 0 = 1 `mod` m
  | k == 1 = a `mod` m
  | even k = modPow ((a ^ 2) `mod` m) (k `div` 2) m
  | otherwise = a * (modPow ((a ^ 2) `mod` m) (k `div` 2) m) `mod` m

-- Returns the smallest integer that is coprime withs phi
smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf phi
  = head [y | y <- [2..(phi+1)], gcd phi y == 1]

-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys
  = undefined

-- RSA encryption/decryption
rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt
  = undefined

rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt
  = undefined

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
toInt :: Char -> Int
toInt
  = undefined

-- Returns the n^th letter
toChar :: Int -> Char
toChar
  = undefined

-- "adds" two letters
add :: Char -> Char -> Char
add
  = undefined

-- "substracts" two letters
substract :: Char -> Char -> Char
substract
  = undefined

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
--
ecbEncrypt :: Char -> String -> String
ecbEncrypt
  = undefined

ecbDecrypt :: Char -> String -> String
ecbDecrypt
  = undefined

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string
--
cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt
  = undefined

cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt
  = undefined
