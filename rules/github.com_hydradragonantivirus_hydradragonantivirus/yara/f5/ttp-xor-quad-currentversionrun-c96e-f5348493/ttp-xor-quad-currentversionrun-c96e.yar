rule TTP_XOR_QUAD_CurrentVersionRun_c96e {
  strings:
    $key_c96e = { 9a 01 [2] be 0f [2] 95 23 [2] bb 01 [2] af 1a [2] a0 00 [2] be 1d [2] bc 1c [2] a7 1a [2] bb 1d [2] a7 32 }

  condition:
    any of them
}