rule TTP_XOR_QUAD_CurrentVersionRun_eeba {
  strings:
    $key_eeba = { bd d5 [2] 99 db [2] b2 f7 [2] 9c d5 [2] 88 ce [2] 87 d4 [2] 99 c9 [2] 9b c8 [2] 80 ce [2] 9c c9 [2] 80 e6 }

  condition:
    any of them
}