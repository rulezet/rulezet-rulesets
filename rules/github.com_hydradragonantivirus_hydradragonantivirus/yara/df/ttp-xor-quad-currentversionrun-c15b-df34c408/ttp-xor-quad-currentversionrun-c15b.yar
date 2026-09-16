rule TTP_XOR_QUAD_CurrentVersionRun_c15b {
  strings:
    $key_c15b = { 92 34 [2] b6 3a [2] 9d 16 [2] b3 34 [2] a7 2f [2] a8 35 [2] b6 28 [2] b4 29 [2] af 2f [2] b3 28 [2] af 07 }

  condition:
    any of them
}