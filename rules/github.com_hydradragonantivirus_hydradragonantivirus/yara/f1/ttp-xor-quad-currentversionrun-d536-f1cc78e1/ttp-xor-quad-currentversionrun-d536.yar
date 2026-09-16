rule TTP_XOR_QUAD_CurrentVersionRun_d536 {
  strings:
    $key_d536 = { 86 59 [2] a2 57 [2] 89 7b [2] a7 59 [2] b3 42 [2] bc 58 [2] a2 45 [2] a0 44 [2] bb 42 [2] a7 45 [2] bb 6a }

  condition:
    any of them
}