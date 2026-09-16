rule TTP_XOR_QUAD_CurrentVersionRun_23ba {
  strings:
    $key_23ba = { 70 d5 [2] 54 db [2] 7f f7 [2] 51 d5 [2] 45 ce [2] 4a d4 [2] 54 c9 [2] 56 c8 [2] 4d ce [2] 51 c9 [2] 4d e6 }

  condition:
    any of them
}