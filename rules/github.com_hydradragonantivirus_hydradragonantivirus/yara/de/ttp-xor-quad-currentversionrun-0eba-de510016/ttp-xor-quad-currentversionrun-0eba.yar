rule TTP_XOR_QUAD_CurrentVersionRun_0eba {
  strings:
    $key_0eba = { 5d d5 [2] 79 db [2] 52 f7 [2] 7c d5 [2] 68 ce [2] 67 d4 [2] 79 c9 [2] 7b c8 [2] 60 ce [2] 7c c9 [2] 60 e6 }

  condition:
    any of them
}