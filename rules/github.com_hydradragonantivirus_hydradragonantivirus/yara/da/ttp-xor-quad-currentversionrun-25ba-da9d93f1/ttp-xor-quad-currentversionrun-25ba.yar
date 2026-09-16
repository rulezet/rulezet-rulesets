rule TTP_XOR_QUAD_CurrentVersionRun_25ba {
  strings:
    $key_25ba = { 76 d5 [2] 52 db [2] 79 f7 [2] 57 d5 [2] 43 ce [2] 4c d4 [2] 52 c9 [2] 50 c8 [2] 4b ce [2] 57 c9 [2] 4b e6 }

  condition:
    any of them
}