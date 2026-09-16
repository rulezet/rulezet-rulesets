rule TTP_XOR_QUAD_CurrentVersionRun_e074 {
  strings:
    $key_e074 = { b3 1b [2] 97 15 [2] bc 39 [2] 92 1b [2] 86 00 [2] 89 1a [2] 97 07 [2] 95 06 [2] 8e 00 [2] 92 07 [2] 8e 28 }

  condition:
    any of them
}