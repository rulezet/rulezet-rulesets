rule TTP_XOR_QUAD_CurrentVersionRun_e057 {
  strings:
    $key_e057 = { b3 38 [2] 97 36 [2] bc 1a [2] 92 38 [2] 86 23 [2] 89 39 [2] 97 24 [2] 95 25 [2] 8e 23 [2] 92 24 [2] 8e 0b }

  condition:
    any of them
}