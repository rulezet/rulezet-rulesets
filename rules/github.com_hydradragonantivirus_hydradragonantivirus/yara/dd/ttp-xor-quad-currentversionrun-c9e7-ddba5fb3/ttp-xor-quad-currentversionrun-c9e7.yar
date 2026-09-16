rule TTP_XOR_QUAD_CurrentVersionRun_c9e7 {
  strings:
    $key_c9e7 = { 9a 88 [2] be 86 [2] 95 aa [2] bb 88 [2] af 93 [2] a0 89 [2] be 94 [2] bc 95 [2] a7 93 [2] bb 94 [2] a7 bb }

  condition:
    any of them
}