rule TTP_XOR_QUAD_CurrentVersionRun_a4c1 {
  strings:
    $key_a4c1 = { f7 ae [2] d3 a0 [2] f8 8c [2] d6 ae [2] c2 b5 [2] cd af [2] d3 b2 [2] d1 b3 [2] ca b5 [2] d6 b2 [2] ca 9d }

  condition:
    any of them
}