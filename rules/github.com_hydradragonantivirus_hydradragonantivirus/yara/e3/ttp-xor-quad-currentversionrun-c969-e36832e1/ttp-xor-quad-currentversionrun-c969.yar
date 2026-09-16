rule TTP_XOR_QUAD_CurrentVersionRun_c969 {
  strings:
    $key_c969 = { 9a 06 [2] be 08 [2] 95 24 [2] bb 06 [2] af 1d [2] a0 07 [2] be 1a [2] bc 1b [2] a7 1d [2] bb 1a [2] a7 35 }

  condition:
    any of them
}