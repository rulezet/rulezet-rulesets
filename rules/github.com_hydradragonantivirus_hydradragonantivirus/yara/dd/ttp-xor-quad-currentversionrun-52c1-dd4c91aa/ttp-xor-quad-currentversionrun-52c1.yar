rule TTP_XOR_QUAD_CurrentVersionRun_52c1 {
  strings:
    $key_52c1 = { 01 ae [2] 25 a0 [2] 0e 8c [2] 20 ae [2] 34 b5 [2] 3b af [2] 25 b2 [2] 27 b3 [2] 3c b5 [2] 20 b2 [2] 3c 9d }

  condition:
    any of them
}