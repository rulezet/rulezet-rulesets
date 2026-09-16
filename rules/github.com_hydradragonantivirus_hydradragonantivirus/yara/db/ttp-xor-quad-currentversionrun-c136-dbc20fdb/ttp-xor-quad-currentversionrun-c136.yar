rule TTP_XOR_QUAD_CurrentVersionRun_c136 {
  strings:
    $key_c136 = { 92 59 [2] b6 57 [2] 9d 7b [2] b3 59 [2] a7 42 [2] a8 58 [2] b6 45 [2] b4 44 [2] af 42 [2] b3 45 [2] af 6a }

  condition:
    any of them
}