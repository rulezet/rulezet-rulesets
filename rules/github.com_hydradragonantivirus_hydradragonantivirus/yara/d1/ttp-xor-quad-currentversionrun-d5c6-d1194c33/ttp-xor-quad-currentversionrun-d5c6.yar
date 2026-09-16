rule TTP_XOR_QUAD_CurrentVersionRun_d5c6 {
  strings:
    $key_d5c6 = { 86 a9 [2] a2 a7 [2] 89 8b [2] a7 a9 [2] b3 b2 [2] bc a8 [2] a2 b5 [2] a0 b4 [2] bb b2 [2] a7 b5 [2] bb 9a }

  condition:
    any of them
}