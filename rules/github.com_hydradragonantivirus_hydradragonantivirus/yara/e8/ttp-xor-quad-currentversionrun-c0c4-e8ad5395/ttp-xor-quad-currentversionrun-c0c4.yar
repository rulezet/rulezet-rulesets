rule TTP_XOR_QUAD_CurrentVersionRun_c0c4 {
  strings:
    $key_c0c4 = { 93 ab [2] b7 a5 [2] 9c 89 [2] b2 ab [2] a6 b0 [2] a9 aa [2] b7 b7 [2] b5 b6 [2] ae b0 [2] b2 b7 [2] ae 98 }

  condition:
    any of them
}