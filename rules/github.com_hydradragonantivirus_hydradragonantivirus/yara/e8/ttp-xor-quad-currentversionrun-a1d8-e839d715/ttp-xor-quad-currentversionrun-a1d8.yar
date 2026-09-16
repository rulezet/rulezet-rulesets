rule TTP_XOR_QUAD_CurrentVersionRun_a1d8 {
  strings:
    $key_a1d8 = { f2 b7 [2] d6 b9 [2] fd 95 [2] d3 b7 [2] c7 ac [2] c8 b6 [2] d6 ab [2] d4 aa [2] cf ac [2] d3 ab [2] cf 84 }

  condition:
    any of them
}