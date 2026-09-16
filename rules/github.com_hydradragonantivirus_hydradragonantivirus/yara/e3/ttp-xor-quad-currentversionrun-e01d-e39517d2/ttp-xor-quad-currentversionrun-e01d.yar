rule TTP_XOR_QUAD_CurrentVersionRun_e01d {
  strings:
    $key_e01d = { b3 72 [2] 97 7c [2] bc 50 [2] 92 72 [2] 86 69 [2] 89 73 [2] 97 6e [2] 95 6f [2] 8e 69 [2] 92 6e [2] 8e 41 }

  condition:
    any of them
}