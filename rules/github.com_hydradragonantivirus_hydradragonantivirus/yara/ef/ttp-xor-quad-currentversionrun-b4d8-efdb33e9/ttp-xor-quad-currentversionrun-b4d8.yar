rule TTP_XOR_QUAD_CurrentVersionRun_b4d8 {
  strings:
    $key_b4d8 = { e7 b7 [2] c3 b9 [2] e8 95 [2] c6 b7 [2] d2 ac [2] dd b6 [2] c3 ab [2] c1 aa [2] da ac [2] c6 ab [2] da 84 }

  condition:
    any of them
}