rule TTP_XOR_QUAD_CurrentVersionRun_c966 {
  strings:
    $key_c966 = { 9a 09 [2] be 07 [2] 95 2b [2] bb 09 [2] af 12 [2] a0 08 [2] be 15 [2] bc 14 [2] a7 12 [2] bb 15 [2] a7 3a }

  condition:
    any of them
}