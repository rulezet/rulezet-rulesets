rule TTP_XOR_QUAD_CurrentVersionRun_c976 {
  strings:
    $key_c976 = { 9a 19 [2] be 17 [2] 95 3b [2] bb 19 [2] af 02 [2] a0 18 [2] be 05 [2] bc 04 [2] a7 02 [2] bb 05 [2] a7 2a }

  condition:
    any of them
}