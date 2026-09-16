rule TTP_XOR_QUAD_CurrentVersionRun_c959 {
  strings:
    $key_c959 = { 9a 36 [2] be 38 [2] 95 14 [2] bb 36 [2] af 2d [2] a0 37 [2] be 2a [2] bc 2b [2] a7 2d [2] bb 2a [2] a7 05 }

  condition:
    any of them
}