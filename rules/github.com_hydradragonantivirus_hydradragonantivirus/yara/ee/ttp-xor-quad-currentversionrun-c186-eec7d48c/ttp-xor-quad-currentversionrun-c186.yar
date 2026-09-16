rule TTP_XOR_QUAD_CurrentVersionRun_c186 {
  strings:
    $key_c186 = { 92 e9 [2] b6 e7 [2] 9d cb [2] b3 e9 [2] a7 f2 [2] a8 e8 [2] b6 f5 [2] b4 f4 [2] af f2 [2] b3 f5 [2] af da }

  condition:
    any of them
}