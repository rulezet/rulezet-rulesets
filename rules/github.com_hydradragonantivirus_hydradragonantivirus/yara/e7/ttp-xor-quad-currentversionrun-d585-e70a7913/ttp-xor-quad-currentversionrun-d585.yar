rule TTP_XOR_QUAD_CurrentVersionRun_d585 {
  strings:
    $key_d585 = { 86 ea [2] a2 e4 [2] 89 c8 [2] a7 ea [2] b3 f1 [2] bc eb [2] a2 f6 [2] a0 f7 [2] bb f1 [2] a7 f6 [2] bb d9 }

  condition:
    any of them
}