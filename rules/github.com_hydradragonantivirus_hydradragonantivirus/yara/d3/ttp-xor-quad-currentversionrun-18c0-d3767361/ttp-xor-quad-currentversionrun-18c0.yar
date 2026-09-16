rule TTP_XOR_QUAD_CurrentVersionRun_18c0 {
  strings:
    $key_18c0 = { 4b af [2] 6f a1 [2] 44 8d [2] 6a af [2] 7e b4 [2] 71 ae [2] 6f b3 [2] 6d b2 [2] 76 b4 [2] 6a b3 [2] 76 9c }

  condition:
    any of them
}