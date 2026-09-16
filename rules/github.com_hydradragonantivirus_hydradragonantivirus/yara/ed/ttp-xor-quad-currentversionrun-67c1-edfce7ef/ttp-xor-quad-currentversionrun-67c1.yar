rule TTP_XOR_QUAD_CurrentVersionRun_67c1 {
  strings:
    $key_67c1 = { 34 ae [2] 10 a0 [2] 3b 8c [2] 15 ae [2] 01 b5 [2] 0e af [2] 10 b2 [2] 12 b3 [2] 09 b5 [2] 15 b2 [2] 09 9d }

  condition:
    any of them
}