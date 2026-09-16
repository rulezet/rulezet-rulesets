rule TTP_XOR_QUAD_CurrentVersionRun_68dd {
  strings:
    $key_68dd = { 3b b2 [2] 1f bc [2] 34 90 [2] 1a b2 [2] 0e a9 [2] 01 b3 [2] 1f ae [2] 1d af [2] 06 a9 [2] 1a ae [2] 06 81 }

  condition:
    any of them
}