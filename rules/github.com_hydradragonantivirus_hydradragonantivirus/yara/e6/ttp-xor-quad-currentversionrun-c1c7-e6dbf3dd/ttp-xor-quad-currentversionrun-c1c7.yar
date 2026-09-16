rule TTP_XOR_QUAD_CurrentVersionRun_c1c7 {
  strings:
    $key_c1c7 = { 92 a8 [2] b6 a6 [2] 9d 8a [2] b3 a8 [2] a7 b3 [2] a8 a9 [2] b6 b4 [2] b4 b5 [2] af b3 [2] b3 b4 [2] af 9b }

  condition:
    any of them
}