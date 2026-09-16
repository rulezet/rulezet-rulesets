rule TTP_XOR_QUAD_CurrentVersionRun_b7c4 {
  strings:
    $key_b7c4 = { e4 ab [2] c0 a5 [2] eb 89 [2] c5 ab [2] d1 b0 [2] de aa [2] c0 b7 [2] c2 b6 [2] d9 b0 [2] c5 b7 [2] d9 98 }

  condition:
    any of them
}