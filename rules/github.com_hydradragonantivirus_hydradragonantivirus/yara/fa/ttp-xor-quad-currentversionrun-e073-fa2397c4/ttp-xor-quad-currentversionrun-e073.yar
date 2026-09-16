rule TTP_XOR_QUAD_CurrentVersionRun_e073 {
  strings:
    $key_e073 = { b3 1c [2] 97 12 [2] bc 3e [2] 92 1c [2] 86 07 [2] 89 1d [2] 97 00 [2] 95 01 [2] 8e 07 [2] 92 00 [2] 8e 2f }

  condition:
    any of them
}