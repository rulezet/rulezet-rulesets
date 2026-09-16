rule TTP_XOR_QUAD_CurrentVersionRun_68a5 {
  strings:
    $key_68a5 = { 3b ca [2] 1f c4 [2] 34 e8 [2] 1a ca [2] 0e d1 [2] 01 cb [2] 1f d6 [2] 1d d7 [2] 06 d1 [2] 1a d6 [2] 06 f9 }

  condition:
    any of them
}