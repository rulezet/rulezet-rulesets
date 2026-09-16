rule TTP_XOR_QUAD_CurrentVersionRun_c94b {
  strings:
    $key_c94b = { 9a 24 [2] be 2a [2] 95 06 [2] bb 24 [2] af 3f [2] a0 25 [2] be 38 [2] bc 39 [2] a7 3f [2] bb 38 [2] a7 17 }

  condition:
    any of them
}