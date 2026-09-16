rule TTP_XOR_QUAD_CurrentVersionRun_c174 {
  strings:
    $key_c174 = { 92 1b [2] b6 15 [2] 9d 39 [2] b3 1b [2] a7 00 [2] a8 1a [2] b6 07 [2] b4 06 [2] af 00 [2] b3 07 [2] af 28 }

  condition:
    any of them
}