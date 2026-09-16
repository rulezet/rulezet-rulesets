rule TTP_XOR_QUAD_CurrentVersionRun_b4c4 {
  strings:
    $key_b4c4 = { e7 ab [2] c3 a5 [2] e8 89 [2] c6 ab [2] d2 b0 [2] dd aa [2] c3 b7 [2] c1 b6 [2] da b0 [2] c6 b7 [2] da 98 }

  condition:
    any of them
}