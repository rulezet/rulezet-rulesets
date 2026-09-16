rule TTP_XOR_QUAD_CurrentVersionRun_c137 {
  strings:
    $key_c137 = { 92 58 [2] b6 56 [2] 9d 7a [2] b3 58 [2] a7 43 [2] a8 59 [2] b6 44 [2] b4 45 [2] af 43 [2] b3 44 [2] af 6b }

  condition:
    any of them
}