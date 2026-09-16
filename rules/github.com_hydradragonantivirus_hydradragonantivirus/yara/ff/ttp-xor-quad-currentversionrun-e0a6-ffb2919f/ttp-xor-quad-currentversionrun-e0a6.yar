rule TTP_XOR_QUAD_CurrentVersionRun_e0a6 {
  strings:
    $key_e0a6 = { b3 c9 [2] 97 c7 [2] bc eb [2] 92 c9 [2] 86 d2 [2] 89 c8 [2] 97 d5 [2] 95 d4 [2] 8e d2 [2] 92 d5 [2] 8e fa }

  condition:
    any of them
}