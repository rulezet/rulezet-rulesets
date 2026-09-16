rule TTP_XOR_QUAD_CurrentVersionRun_e03d {
  strings:
    $key_e03d = { b3 52 [2] 97 5c [2] bc 70 [2] 92 52 [2] 86 49 [2] 89 53 [2] 97 4e [2] 95 4f [2] 8e 49 [2] 92 4e [2] 8e 61 }

  condition:
    any of them
}