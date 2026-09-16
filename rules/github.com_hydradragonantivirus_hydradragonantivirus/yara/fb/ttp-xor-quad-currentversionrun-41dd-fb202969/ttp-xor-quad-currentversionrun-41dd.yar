rule TTP_XOR_QUAD_CurrentVersionRun_41dd {
  strings:
    $key_41dd = { 12 b2 [2] 36 bc [2] 1d 90 [2] 33 b2 [2] 27 a9 [2] 28 b3 [2] 36 ae [2] 34 af [2] 2f a9 [2] 33 ae [2] 2f 81 }

  condition:
    any of them
}