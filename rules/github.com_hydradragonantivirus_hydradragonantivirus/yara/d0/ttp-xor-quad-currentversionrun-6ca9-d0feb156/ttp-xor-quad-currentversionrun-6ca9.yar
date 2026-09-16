rule TTP_XOR_QUAD_CurrentVersionRun_6ca9 {
  strings:
    $key_6ca9 = { 3f c6 [2] 1b c8 [2] 30 e4 [2] 1e c6 [2] 0a dd [2] 05 c7 [2] 1b da [2] 19 db [2] 02 dd [2] 1e da [2] 02 f5 }

  condition:
    any of them
}