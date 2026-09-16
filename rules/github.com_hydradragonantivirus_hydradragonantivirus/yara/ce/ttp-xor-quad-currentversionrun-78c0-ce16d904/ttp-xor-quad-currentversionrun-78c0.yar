rule TTP_XOR_QUAD_CurrentVersionRun_78c0 {
  strings:
    $key_78c0 = { 2b af [2] 0f a1 [2] 24 8d [2] 0a af [2] 1e b4 [2] 11 ae [2] 0f b3 [2] 0d b2 [2] 16 b4 [2] 0a b3 [2] 16 9c }

  condition:
    any of them
}