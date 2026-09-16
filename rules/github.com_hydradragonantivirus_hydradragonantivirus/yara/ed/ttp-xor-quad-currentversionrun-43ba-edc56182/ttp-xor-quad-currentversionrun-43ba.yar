rule TTP_XOR_QUAD_CurrentVersionRun_43ba {
  strings:
    $key_43ba = { 10 d5 [2] 34 db [2] 1f f7 [2] 31 d5 [2] 25 ce [2] 2a d4 [2] 34 c9 [2] 36 c8 [2] 2d ce [2] 31 c9 [2] 2d e6 }

  condition:
    any of them
}