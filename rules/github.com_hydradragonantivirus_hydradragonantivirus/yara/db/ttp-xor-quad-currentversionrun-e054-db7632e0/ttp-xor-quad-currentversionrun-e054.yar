rule TTP_XOR_QUAD_CurrentVersionRun_e054 {
  strings:
    $key_e054 = { b3 3b [2] 97 35 [2] bc 19 [2] 92 3b [2] 86 20 [2] 89 3a [2] 97 27 [2] 95 26 [2] 8e 20 [2] 92 27 [2] 8e 08 }

  condition:
    any of them
}