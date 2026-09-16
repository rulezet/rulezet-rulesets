rule TTP_XOR_QUAD_CurrentVersionRun_4ca9 {
  strings:
    $key_4ca9 = { 1f c6 [2] 3b c8 [2] 10 e4 [2] 3e c6 [2] 2a dd [2] 25 c7 [2] 3b da [2] 39 db [2] 22 dd [2] 3e da [2] 22 f5 }

  condition:
    any of them
}