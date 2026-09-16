rule TTP_XOR_QUAD_CurrentVersionRun_c90e {
  strings:
    $key_c90e = { 9a 61 [2] be 6f [2] 95 43 [2] bb 61 [2] af 7a [2] a0 60 [2] be 7d [2] bc 7c [2] a7 7a [2] bb 7d [2] a7 52 }

  condition:
    any of them
}