rule TTP_XOR_QUAD_CurrentVersionRun_31ba {
  strings:
    $key_31ba = { 62 d5 [2] 46 db [2] 6d f7 [2] 43 d5 [2] 57 ce [2] 58 d4 [2] 46 c9 [2] 44 c8 [2] 5f ce [2] 43 c9 [2] 5f e6 }

  condition:
    any of them
}