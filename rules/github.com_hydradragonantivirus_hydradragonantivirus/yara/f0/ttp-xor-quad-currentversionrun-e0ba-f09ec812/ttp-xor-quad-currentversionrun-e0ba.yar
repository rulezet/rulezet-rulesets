rule TTP_XOR_QUAD_CurrentVersionRun_e0ba {
  strings:
    $key_e0ba = { b3 d5 [2] 97 db [2] bc f7 [2] 92 d5 [2] 86 ce [2] 89 d4 [2] 97 c9 [2] 95 c8 [2] 8e ce [2] 92 c9 [2] 8e e6 }

  condition:
    any of them
}