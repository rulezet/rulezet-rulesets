rule TTP_XOR_QUAD_CurrentVersionRun_c8b5 {
  strings:
    $key_c8b5 = { 9b da [2] bf d4 [2] 94 f8 [2] ba da [2] ae c1 [2] a1 db [2] bf c6 [2] bd c7 [2] a6 c1 [2] ba c6 [2] a6 e9 }

  condition:
    any of them
}