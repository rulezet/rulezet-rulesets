rule TTP_XOR_QUAD_CurrentVersionRun_79ba {
  strings:
    $key_79ba = { 2a d5 [2] 0e db [2] 25 f7 [2] 0b d5 [2] 1f ce [2] 10 d4 [2] 0e c9 [2] 0c c8 [2] 17 ce [2] 0b c9 [2] 17 e6 }

  condition:
    any of them
}