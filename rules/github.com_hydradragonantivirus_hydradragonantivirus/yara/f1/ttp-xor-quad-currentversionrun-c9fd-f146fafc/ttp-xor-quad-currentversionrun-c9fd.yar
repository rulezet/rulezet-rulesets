rule TTP_XOR_QUAD_CurrentVersionRun_c9fd {
  strings:
    $key_c9fd = { 9a 92 [2] be 9c [2] 95 b0 [2] bb 92 [2] af 89 [2] a0 93 [2] be 8e [2] bc 8f [2] a7 89 [2] bb 8e [2] a7 a1 }

  condition:
    any of them
}