rule TTP_XOR_QUAD_CurrentVersionRun_08ba {
  strings:
    $key_08ba = { 5b d5 [2] 7f db [2] 54 f7 [2] 7a d5 [2] 6e ce [2] 61 d4 [2] 7f c9 [2] 7d c8 [2] 66 ce [2] 7a c9 [2] 66 e6 }

  condition:
    any of them
}