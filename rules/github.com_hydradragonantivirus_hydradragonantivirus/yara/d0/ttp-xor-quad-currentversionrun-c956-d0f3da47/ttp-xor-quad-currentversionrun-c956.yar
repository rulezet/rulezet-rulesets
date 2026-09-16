rule TTP_XOR_QUAD_CurrentVersionRun_c956 {
  strings:
    $key_c956 = { 9a 39 [2] be 37 [2] 95 1b [2] bb 39 [2] af 22 [2] a0 38 [2] be 25 [2] bc 24 [2] a7 22 [2] bb 25 [2] a7 0a }

  condition:
    any of them
}