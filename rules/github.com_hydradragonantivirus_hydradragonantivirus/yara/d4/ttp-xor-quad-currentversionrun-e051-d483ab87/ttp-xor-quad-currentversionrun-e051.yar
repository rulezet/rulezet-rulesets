rule TTP_XOR_QUAD_CurrentVersionRun_e051 {
  strings:
    $key_e051 = { b3 3e [2] 97 30 [2] bc 1c [2] 92 3e [2] 86 25 [2] 89 3f [2] 97 22 [2] 95 23 [2] 8e 25 [2] 92 22 [2] 8e 0d }

  condition:
    any of them
}