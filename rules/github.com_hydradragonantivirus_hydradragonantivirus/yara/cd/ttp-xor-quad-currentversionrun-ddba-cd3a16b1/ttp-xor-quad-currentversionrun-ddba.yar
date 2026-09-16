rule TTP_XOR_QUAD_CurrentVersionRun_ddba {
  strings:
    $key_ddba = { 8e d5 [2] aa db [2] 81 f7 [2] af d5 [2] bb ce [2] b4 d4 [2] aa c9 [2] a8 c8 [2] b3 ce [2] af c9 [2] b3 e6 }

  condition:
    any of them
}