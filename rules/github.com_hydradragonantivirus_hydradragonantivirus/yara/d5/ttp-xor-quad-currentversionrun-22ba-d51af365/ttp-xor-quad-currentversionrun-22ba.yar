rule TTP_XOR_QUAD_CurrentVersionRun_22ba {
  strings:
    $key_22ba = { 71 d5 [2] 55 db [2] 7e f7 [2] 50 d5 [2] 44 ce [2] 4b d4 [2] 55 c9 [2] 57 c8 [2] 4c ce [2] 50 c9 [2] 4c e6 }

  condition:
    any of them
}