rule TTP_XOR_QUAD_CurrentVersionRun_e047 {
  strings:
    $key_e047 = { b3 28 [2] 97 26 [2] bc 0a [2] 92 28 [2] 86 33 [2] 89 29 [2] 97 34 [2] 95 35 [2] 8e 33 [2] 92 34 [2] 8e 1b }

  condition:
    any of them
}