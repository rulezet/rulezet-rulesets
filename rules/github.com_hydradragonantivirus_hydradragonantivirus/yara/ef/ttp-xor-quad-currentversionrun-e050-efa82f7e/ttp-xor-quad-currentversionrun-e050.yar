rule TTP_XOR_QUAD_CurrentVersionRun_e050 {
  strings:
    $key_e050 = { b3 3f [2] 97 31 [2] bc 1d [2] 92 3f [2] 86 24 [2] 89 3e [2] 97 23 [2] 95 22 [2] 8e 24 [2] 92 23 [2] 8e 0c }

  condition:
    any of them
}