rule TTP_XOR_QUAD_CurrentVersionRun_63ba {
  strings:
    $key_63ba = { 30 d5 [2] 14 db [2] 3f f7 [2] 11 d5 [2] 05 ce [2] 0a d4 [2] 14 c9 [2] 16 c8 [2] 0d ce [2] 11 c9 [2] 0d e6 }

  condition:
    any of them
}