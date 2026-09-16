rule TTP_XOR_QUAD_CurrentVersionRun_b0d8 {
  strings:
    $key_b0d8 = { e3 b7 [2] c7 b9 [2] ec 95 [2] c2 b7 [2] d6 ac [2] d9 b6 [2] c7 ab [2] c5 aa [2] de ac [2] c2 ab [2] de 84 }

  condition:
    any of them
}