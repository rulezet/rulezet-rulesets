rule TTP_XOR_QUAD_CurrentVersionRun_e064 {
  strings:
    $key_e064 = { b3 0b [2] 97 05 [2] bc 29 [2] 92 0b [2] 86 10 [2] 89 0a [2] 97 17 [2] 95 16 [2] 8e 10 [2] 92 17 [2] 8e 38 }

  condition:
    any of them
}