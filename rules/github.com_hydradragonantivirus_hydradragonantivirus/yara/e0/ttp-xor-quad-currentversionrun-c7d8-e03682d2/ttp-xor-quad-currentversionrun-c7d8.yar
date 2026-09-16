rule TTP_XOR_QUAD_CurrentVersionRun_c7d8 {
  strings:
    $key_c7d8 = { 94 b7 [2] b0 b9 [2] 9b 95 [2] b5 b7 [2] a1 ac [2] ae b6 [2] b0 ab [2] b2 aa [2] a9 ac [2] b5 ab [2] a9 84 }

  condition:
    any of them
}