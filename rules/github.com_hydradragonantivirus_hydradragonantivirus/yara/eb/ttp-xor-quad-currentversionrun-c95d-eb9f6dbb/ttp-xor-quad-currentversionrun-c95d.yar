rule TTP_XOR_QUAD_CurrentVersionRun_c95d {
  strings:
    $key_c95d = { 9a 32 [2] be 3c [2] 95 10 [2] bb 32 [2] af 29 [2] a0 33 [2] be 2e [2] bc 2f [2] a7 29 [2] bb 2e [2] a7 01 }

  condition:
    any of them
}