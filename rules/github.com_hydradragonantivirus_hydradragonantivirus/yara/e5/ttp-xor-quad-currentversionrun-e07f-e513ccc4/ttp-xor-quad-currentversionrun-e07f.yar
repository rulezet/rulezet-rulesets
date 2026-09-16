rule TTP_XOR_QUAD_CurrentVersionRun_e07f {
  strings:
    $key_e07f = { b3 10 [2] 97 1e [2] bc 32 [2] 92 10 [2] 86 0b [2] 89 11 [2] 97 0c [2] 95 0d [2] 8e 0b [2] 92 0c [2] 8e 23 }

  condition:
    any of them
}