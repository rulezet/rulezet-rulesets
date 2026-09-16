rule TTP_XOR_QUAD_CurrentVersionRun_c96d {
  strings:
    $key_c96d = { 9a 02 [2] be 0c [2] 95 20 [2] bb 02 [2] af 19 [2] a0 03 [2] be 1e [2] bc 1f [2] a7 19 [2] bb 1e [2] a7 31 }

  condition:
    any of them
}