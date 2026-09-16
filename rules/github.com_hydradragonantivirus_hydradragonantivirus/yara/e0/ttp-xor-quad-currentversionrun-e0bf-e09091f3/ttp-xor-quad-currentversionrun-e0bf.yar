rule TTP_XOR_QUAD_CurrentVersionRun_e0bf {
  strings:
    $key_e0bf = { b3 d0 [2] 97 de [2] bc f2 [2] 92 d0 [2] 86 cb [2] 89 d1 [2] 97 cc [2] 95 cd [2] 8e cb [2] 92 cc [2] 8e e3 }

  condition:
    any of them
}