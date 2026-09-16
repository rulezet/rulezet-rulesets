rule TTP_XOR_QUAD_CurrentVersionRun_c0d8 {
  strings:
    $key_c0d8 = { 93 b7 [2] b7 b9 [2] 9c 95 [2] b2 b7 [2] a6 ac [2] a9 b6 [2] b7 ab [2] b5 aa [2] ae ac [2] b2 ab [2] ae 84 }

  condition:
    any of them
}