rule TTP_XOR_QUAD_CurrentVersionRun_c94e {
  strings:
    $key_c94e = { 9a 21 [2] be 2f [2] 95 03 [2] bb 21 [2] af 3a [2] a0 20 [2] be 3d [2] bc 3c [2] a7 3a [2] bb 3d [2] a7 12 }

  condition:
    any of them
}