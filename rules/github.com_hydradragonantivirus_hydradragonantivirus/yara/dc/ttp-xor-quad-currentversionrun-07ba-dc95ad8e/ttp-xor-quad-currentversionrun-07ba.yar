rule TTP_XOR_QUAD_CurrentVersionRun_07ba {
  strings:
    $key_07ba = { 54 d5 [2] 70 db [2] 5b f7 [2] 75 d5 [2] 61 ce [2] 6e d4 [2] 70 c9 [2] 72 c8 [2] 69 ce [2] 75 c9 [2] 69 e6 }

  condition:
    any of them
}