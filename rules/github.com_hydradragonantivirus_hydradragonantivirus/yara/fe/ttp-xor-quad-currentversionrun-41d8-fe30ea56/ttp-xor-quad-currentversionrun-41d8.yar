rule TTP_XOR_QUAD_CurrentVersionRun_41d8 {
  strings:
    $key_41d8 = { 12 b7 [2] 36 b9 [2] 1d 95 [2] 33 b7 [2] 27 ac [2] 28 b6 [2] 36 ab [2] 34 aa [2] 2f ac [2] 33 ab [2] 2f 84 }

  condition:
    any of them
}