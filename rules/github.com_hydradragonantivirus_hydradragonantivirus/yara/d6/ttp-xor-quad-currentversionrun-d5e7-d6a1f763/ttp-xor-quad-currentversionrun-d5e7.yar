rule TTP_XOR_QUAD_CurrentVersionRun_d5e7 {
  strings:
    $key_d5e7 = { 86 88 [2] a2 86 [2] 89 aa [2] a7 88 [2] b3 93 [2] bc 89 [2] a2 94 [2] a0 95 [2] bb 93 [2] a7 94 [2] bb bb }

  condition:
    any of them
}