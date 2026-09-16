rule TTP_XOR_QUAD_CurrentVersionRun_e063 {
  strings:
    $key_e063 = { b3 0c [2] 97 02 [2] bc 2e [2] 92 0c [2] 86 17 [2] 89 0d [2] 97 10 [2] 95 11 [2] 8e 17 [2] 92 10 [2] 8e 3f }

  condition:
    any of them
}