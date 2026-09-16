rule TTP_XOR_QUAD_CurrentVersionRun_e06f {
  strings:
    $key_e06f = { b3 00 [2] 97 0e [2] bc 22 [2] 92 00 [2] 86 1b [2] 89 01 [2] 97 1c [2] 95 1d [2] 8e 1b [2] 92 1c [2] 8e 33 }

  condition:
    any of them
}