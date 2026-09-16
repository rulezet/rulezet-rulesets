rule TTP_XOR_QUAD_CurrentVersionRun_e07e {
  strings:
    $key_e07e = { b3 11 [2] 97 1f [2] bc 33 [2] 92 11 [2] 86 0a [2] 89 10 [2] 97 0d [2] 95 0c [2] 8e 0a [2] 92 0d [2] 8e 22 }

  condition:
    any of them
}