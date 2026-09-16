rule TTP_XOR_QUAD_CurrentVersionRun_d9d8 {
  strings:
    $key_d9d8 = { 8a b7 [2] ae b9 [2] 85 95 [2] ab b7 [2] bf ac [2] b0 b6 [2] ae ab [2] ac aa [2] b7 ac [2] ab ab [2] b7 84 }

  condition:
    any of them
}