rule TTP_XOR_QUAD_CurrentVersionRun_58a9 {
  strings:
    $key_58a9 = { 0b c6 [2] 2f c8 [2] 04 e4 [2] 2a c6 [2] 3e dd [2] 31 c7 [2] 2f da [2] 2d db [2] 36 dd [2] 2a da [2] 36 f5 }

  condition:
    any of them
}