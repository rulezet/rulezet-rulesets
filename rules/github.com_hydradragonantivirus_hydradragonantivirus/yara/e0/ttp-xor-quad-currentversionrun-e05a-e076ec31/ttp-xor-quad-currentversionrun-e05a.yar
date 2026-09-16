rule TTP_XOR_QUAD_CurrentVersionRun_e05a {
  strings:
    $key_e05a = { b3 35 [2] 97 3b [2] bc 17 [2] 92 35 [2] 86 2e [2] 89 34 [2] 97 29 [2] 95 28 [2] 8e 2e [2] 92 29 [2] 8e 06 }

  condition:
    any of them
}