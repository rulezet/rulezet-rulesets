rule TTP_XOR_QUAD_CurrentVersionRun_d5d8 {
  strings:
    $key_d5d8 = { 86 b7 [2] a2 b9 [2] 89 95 [2] a7 b7 [2] b3 ac [2] bc b6 [2] a2 ab [2] a0 aa [2] bb ac [2] a7 ab [2] bb 84 }

  condition:
    any of them
}