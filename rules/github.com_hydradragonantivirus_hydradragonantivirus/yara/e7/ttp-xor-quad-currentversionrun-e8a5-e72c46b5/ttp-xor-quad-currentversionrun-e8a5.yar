rule TTP_XOR_QUAD_CurrentVersionRun_e8a5 {
  strings:
    $key_e8a5 = { bb ca [2] 9f c4 [2] b4 e8 [2] 9a ca [2] 8e d1 [2] 81 cb [2] 9f d6 [2] 9d d7 [2] 86 d1 [2] 9a d6 [2] 86 f9 }

  condition:
    any of them
}