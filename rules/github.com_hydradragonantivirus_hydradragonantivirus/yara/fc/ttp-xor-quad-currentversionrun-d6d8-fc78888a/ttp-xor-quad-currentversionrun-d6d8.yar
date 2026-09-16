rule TTP_XOR_QUAD_CurrentVersionRun_d6d8 {
  strings:
    $key_d6d8 = { 85 b7 [2] a1 b9 [2] 8a 95 [2] a4 b7 [2] b0 ac [2] bf b6 [2] a1 ab [2] a3 aa [2] b8 ac [2] a4 ab [2] b8 84 }

  condition:
    any of them
}