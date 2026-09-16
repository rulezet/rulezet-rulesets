rule TTP_XOR_QUAD_CurrentVersionRun_c923 {
  strings:
    $key_c923 = { 9a 4c [2] be 42 [2] 95 6e [2] bb 4c [2] af 57 [2] a0 4d [2] be 50 [2] bc 51 [2] a7 57 [2] bb 50 [2] a7 7f }

  condition:
    any of them
}