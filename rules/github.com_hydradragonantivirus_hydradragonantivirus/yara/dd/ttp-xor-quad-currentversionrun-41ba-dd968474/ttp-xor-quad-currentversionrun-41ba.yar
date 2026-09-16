rule TTP_XOR_QUAD_CurrentVersionRun_41ba {
  strings:
    $key_41ba = { 12 d5 [2] 36 db [2] 1d f7 [2] 33 d5 [2] 27 ce [2] 28 d4 [2] 36 c9 [2] 34 c8 [2] 2f ce [2] 33 c9 [2] 2f e6 }

  condition:
    any of them
}