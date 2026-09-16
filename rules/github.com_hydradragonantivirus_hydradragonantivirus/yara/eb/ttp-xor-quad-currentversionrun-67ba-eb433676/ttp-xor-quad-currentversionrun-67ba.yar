rule TTP_XOR_QUAD_CurrentVersionRun_67ba {
  strings:
    $key_67ba = { 34 d5 [2] 10 db [2] 3b f7 [2] 15 d5 [2] 01 ce [2] 0e d4 [2] 10 c9 [2] 12 c8 [2] 09 ce [2] 15 c9 [2] 09 e6 }

  condition:
    any of them
}