rule TTP_XOR_QUAD_CurrentVersionRun_46c1 {
  strings:
    $key_46c1 = { 15 ae [2] 31 a0 [2] 1a 8c [2] 34 ae [2] 20 b5 [2] 2f af [2] 31 b2 [2] 33 b3 [2] 28 b5 [2] 34 b2 [2] 28 9d }

  condition:
    any of them
}