rule TTP_XOR_QUAD_CurrentVersionRun_c167 {
  strings:
    $key_c167 = { 92 08 [2] b6 06 [2] 9d 2a [2] b3 08 [2] a7 13 [2] a8 09 [2] b6 14 [2] b4 15 [2] af 13 [2] b3 14 [2] af 3b }

  condition:
    any of them
}