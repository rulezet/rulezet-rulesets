rule TTP_XOR_QUAD_CurrentVersionRun_e001 {
  strings:
    $key_e001 = { b3 6e [2] 97 60 [2] bc 4c [2] 92 6e [2] 86 75 [2] 89 6f [2] 97 72 [2] 95 73 [2] 8e 75 [2] 92 72 [2] 8e 5d }

  condition:
    any of them
}