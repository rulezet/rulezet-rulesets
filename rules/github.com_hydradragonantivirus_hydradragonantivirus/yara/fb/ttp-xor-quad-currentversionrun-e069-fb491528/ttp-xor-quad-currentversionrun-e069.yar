rule TTP_XOR_QUAD_CurrentVersionRun_e069 {
  strings:
    $key_e069 = { b3 06 [2] 97 08 [2] bc 24 [2] 92 06 [2] 86 1d [2] 89 07 [2] 97 1a [2] 95 1b [2] 8e 1d [2] 92 1a [2] 8e 35 }

  condition:
    any of them
}