rule TTP_XOR_QUAD_CurrentVersionRun_64c1 {
  strings:
    $key_64c1 = { 37 ae [2] 13 a0 [2] 38 8c [2] 16 ae [2] 02 b5 [2] 0d af [2] 13 b2 [2] 11 b3 [2] 0a b5 [2] 16 b2 [2] 0a 9d }

  condition:
    any of them
}