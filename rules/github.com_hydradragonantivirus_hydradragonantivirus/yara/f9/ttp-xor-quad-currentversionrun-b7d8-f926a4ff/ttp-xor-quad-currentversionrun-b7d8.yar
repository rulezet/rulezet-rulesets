rule TTP_XOR_QUAD_CurrentVersionRun_b7d8 {
  strings:
    $key_b7d8 = { e4 b7 [2] c0 b9 [2] eb 95 [2] c5 b7 [2] d1 ac [2] de b6 [2] c0 ab [2] c2 aa [2] d9 ac [2] c5 ab [2] d9 84 }

  condition:
    any of them
}