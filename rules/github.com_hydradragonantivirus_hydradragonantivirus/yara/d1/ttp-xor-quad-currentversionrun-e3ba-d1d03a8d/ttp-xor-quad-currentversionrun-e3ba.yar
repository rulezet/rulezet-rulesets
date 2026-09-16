rule TTP_XOR_QUAD_CurrentVersionRun_e3ba {
  strings:
    $key_e3ba = { b0 d5 [2] 94 db [2] bf f7 [2] 91 d5 [2] 85 ce [2] 8a d4 [2] 94 c9 [2] 96 c8 [2] 8d ce [2] 91 c9 [2] 8d e6 }

  condition:
    any of them
}