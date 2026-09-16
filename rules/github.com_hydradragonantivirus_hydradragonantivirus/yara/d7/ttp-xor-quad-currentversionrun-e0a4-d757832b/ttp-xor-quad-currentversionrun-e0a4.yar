rule TTP_XOR_QUAD_CurrentVersionRun_e0a4 {
  strings:
    $key_e0a4 = { b3 cb [2] 97 c5 [2] bc e9 [2] 92 cb [2] 86 d0 [2] 89 ca [2] 97 d7 [2] 95 d6 [2] 8e d0 [2] 92 d7 [2] 8e f8 }

  condition:
    any of them
}