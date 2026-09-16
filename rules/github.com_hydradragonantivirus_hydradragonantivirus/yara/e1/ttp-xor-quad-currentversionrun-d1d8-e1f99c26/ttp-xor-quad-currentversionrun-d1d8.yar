rule TTP_XOR_QUAD_CurrentVersionRun_d1d8 {
  strings:
    $key_d1d8 = { 82 b7 [2] a6 b9 [2] 8d 95 [2] a3 b7 [2] b7 ac [2] b8 b6 [2] a6 ab [2] a4 aa [2] bf ac [2] a3 ab [2] bf 84 }

  condition:
    any of them
}