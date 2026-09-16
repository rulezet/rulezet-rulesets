rule TTP_XOR_QUAD_CurrentVersionRun_e0d6 {
  strings:
    $key_e0d6 = { b3 b9 [2] 97 b7 [2] bc 9b [2] 92 b9 [2] 86 a2 [2] 89 b8 [2] 97 a5 [2] 95 a4 [2] 8e a2 [2] 92 a5 [2] 8e 8a }

  condition:
    any of them
}