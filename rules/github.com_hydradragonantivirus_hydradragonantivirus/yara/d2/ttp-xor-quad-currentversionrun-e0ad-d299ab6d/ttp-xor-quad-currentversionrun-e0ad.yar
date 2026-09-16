rule TTP_XOR_QUAD_CurrentVersionRun_e0ad {
  strings:
    $key_e0ad = { b3 c2 [2] 97 cc [2] bc e0 [2] 92 c2 [2] 86 d9 [2] 89 c3 [2] 97 de [2] 95 df [2] 8e d9 [2] 92 de [2] 8e f1 }

  condition:
    any of them
}