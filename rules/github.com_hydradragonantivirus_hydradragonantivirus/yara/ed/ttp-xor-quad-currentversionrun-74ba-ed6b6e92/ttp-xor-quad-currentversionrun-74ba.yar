rule TTP_XOR_QUAD_CurrentVersionRun_74ba {
  strings:
    $key_74ba = { 27 d5 [2] 03 db [2] 28 f7 [2] 06 d5 [2] 12 ce [2] 1d d4 [2] 03 c9 [2] 01 c8 [2] 1a ce [2] 06 c9 [2] 1a e6 }

  condition:
    any of them
}