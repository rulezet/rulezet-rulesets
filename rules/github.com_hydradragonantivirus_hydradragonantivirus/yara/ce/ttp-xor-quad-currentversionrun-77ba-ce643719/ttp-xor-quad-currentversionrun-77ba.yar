rule TTP_XOR_QUAD_CurrentVersionRun_77ba {
  strings:
    $key_77ba = { 24 d5 [2] 00 db [2] 2b f7 [2] 05 d5 [2] 11 ce [2] 1e d4 [2] 00 c9 [2] 02 c8 [2] 19 ce [2] 05 c9 [2] 19 e6 }

  condition:
    any of them
}