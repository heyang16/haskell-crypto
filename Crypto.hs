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
computeCoeffs a 0 = (1, 0)
computeCoeffs a b = (v, u - q * v)
  where 
    (q, r) = quotRem a b
    (u, v) = computeCoeffs b r

-- Inverse of a modulo m
-- Returns undefined if a does not have a multiplicative inverse (mod m)
inverse :: Int -> Int -> Int
inverse a m
  | gcd a m /= 1 = undefined
  | otherwise = let (u, v) = computeCoeffs a m in u `mod` m

-- Calculates (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a 0 m = 1 `mod` m -- base cases
modPow a 1 m = a `mod` m -- base cases
modPow a k m
  | even k = modPow n (k `div` 2) m --recursive steps
  | otherwise = a * modPow n (k `div` 2) m `mod` m --recursive steps
  where
    n = (a `mod` m ) ^ 2 `mod` m

-- Returns the smallest integer that is coprime withs phi
smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf a
  = head [y | y <- [2..(a + 1)], gcd a y == 1]

-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
-- Runs the RSA key generation algorithm and returns the key pair
-- ((e, N),(d, N)) as described above.
-- 1. Choose two distinct prime numbers p and q.
-- 2. Compute the RSA modulus N = p q
-- 3. Choose an integer e > 1 such that gcd(e,(p − 1)(q − 1)) = 1
-- 4. Compute an integer d such that e d = 1 (mod (p − 1)(q − 1))
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q
  = ((e, n), (d, n))
  where
    n = p * q
    k = (p - 1) * (q - 1)
    e = smallestCoPrimeOf k
    d = inverse e k

-- RSA encryption/decryption
-- takes a plain text x and a public key (e, n) and returns the ciphertext x^e mod n
rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt x (e, n)
  = modPow x e n

-- takes a plain text x and a private key (d, n) and returns the ciphertext x^d mod n,
-- the same operations as rsaEncrypt
rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt = rsaEncrypt

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
-- Returns undefined if letter is not in the alphabet
toInt :: Char -> Int
toInt c
  | ord c >= ord 'a' && ord c <= ord 'z' = ord c - ord 'a'
  | ord c >= ord 'A' && ord c <= ord 'Z' = ord c - ord 'A'
  | otherwise = undefined

-- Returns the n^th letter (lowercase)
-- Returns undefined if letter is not in the alphabet
toChar :: Int -> Char
toChar n
  | n >= 0 && n <= 25 = chr (n + ord 'a')
  | otherwise = undefined

-- "adds" two letters
-- if index exceeds 26, we use index mod 26 instead
add :: Char -> Char -> Char
add a b
  = toChar i
  where
    n = toInt a + toInt b
    i = n `mod` 26

-- "substracts" two letters
-- if index exceeds 26, we use index mod 26 instead
substract :: Char -> Char -> Char
substract a b
  = toChar i
  where
    n = toInt a - toInt b + 260 -- adding 260 ensures that n is positive
    i = n `mod` 26

-- same as subtract but subtracts a from b instead of b from a
-- for use in ecbEncrypt
substractRev :: Char -> Char -> Char
substractRev a b
  = toChar i
  where
    n = toInt b - toInt a + 260 -- adding 260 ensures that n is positive
    i = n `mod` 26

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
-- encrypts all characters in a string m by adding their indexes by a key k
ecbEncrypt :: Char -> String -> String
ecbEncrypt k = map (add k) 

-- the inverse function of ecbEncrypt
ecbDecrypt :: Char -> String -> String
ecbDecrypt k = map (substractRev k) 

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string
-- each character x is encrypted to a character c, where
-- c1 = (x1 ⊕ iv) ⊕ k
-- ci = (xi ⊕ ci−1) ⊕ for 1 < i ≤ l, where l is the length of m
cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt k v "" = ""
cbcEncrypt k v (c:cs) 
  = a : cbcEncrypt k a cs
  where
    a = add (add c v) k

-- the inverse function of cbcEncrypt
cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt k v "" = ""
cbcDecrypt k v (c:cs) 
  = a : cbcDecrypt k c cs
  where
    a = substract (substract c v) k
