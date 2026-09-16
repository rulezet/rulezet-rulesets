rule TTP_XOR_QUAD_CurrentVersionRun_c96c {
  strings:
    $key_c96c = { 9a 03 [2] be 0d [2] 95 21 [2] bb 03 [2] af 18 [2] a0 02 [2] be 1f [2] bc 1e [2] a7 18 [2] bb 1f [2] a7 30 }

  condition:
    any of them
}