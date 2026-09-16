rule TTP_XOR_QUAD_CurrentVersionRun_da7d {
  strings:
    $key_da7d = { 89 12 [2] ad 1c [2] 86 30 [2] a8 12 [2] bc 09 [2] b3 13 [2] ad 0e [2] af 0f [2] b4 09 [2] a8 0e [2] b4 21 }

  condition:
    any of them
}