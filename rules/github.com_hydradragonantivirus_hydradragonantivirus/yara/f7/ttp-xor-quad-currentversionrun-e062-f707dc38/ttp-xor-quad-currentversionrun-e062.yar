rule TTP_XOR_QUAD_CurrentVersionRun_e062 {
  strings:
    $key_e062 = { b3 0d [2] 97 03 [2] bc 2f [2] 92 0d [2] 86 16 [2] 89 0c [2] 97 11 [2] 95 10 [2] 8e 16 [2] 92 11 [2] 8e 3e }

  condition:
    any of them
}