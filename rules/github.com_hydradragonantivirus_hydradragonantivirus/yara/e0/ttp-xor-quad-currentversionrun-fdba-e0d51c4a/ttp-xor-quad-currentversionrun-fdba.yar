rule TTP_XOR_QUAD_CurrentVersionRun_fdba {
  strings:
    $key_fdba = { ae d5 [2] 8a db [2] a1 f7 [2] 8f d5 [2] 9b ce [2] 94 d4 [2] 8a c9 [2] 88 c8 [2] 93 ce [2] 8f c9 [2] 93 e6 }

  condition:
    any of them
}