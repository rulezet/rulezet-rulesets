rule TTP_XOR_QUAD_CurrentVersionRun_e0b8 {
  strings:
    $key_e0b8 = { b3 d7 [2] 97 d9 [2] bc f5 [2] 92 d7 [2] 86 cc [2] 89 d6 [2] 97 cb [2] 95 ca [2] 8e cc [2] 92 cb [2] 8e e4 }

  condition:
    any of them
}