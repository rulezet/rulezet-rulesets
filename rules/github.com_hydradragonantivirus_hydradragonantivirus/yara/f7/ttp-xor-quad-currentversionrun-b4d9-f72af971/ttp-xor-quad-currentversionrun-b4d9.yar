rule TTP_XOR_QUAD_CurrentVersionRun_b4d9 {
  strings:
    $key_b4d9 = { e7 b6 [2] c3 b8 [2] e8 94 [2] c6 b6 [2] d2 ad [2] dd b7 [2] c3 aa [2] c1 ab [2] da ad [2] c6 aa [2] da 85 }

  condition:
    any of them
}