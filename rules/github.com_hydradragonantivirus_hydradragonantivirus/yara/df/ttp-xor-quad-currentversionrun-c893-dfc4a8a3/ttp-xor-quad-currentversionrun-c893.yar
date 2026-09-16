rule TTP_XOR_QUAD_CurrentVersionRun_c893 {
  strings:
    $key_c893 = { 9b fc [2] bf f2 [2] 94 de [2] ba fc [2] ae e7 [2] a1 fd [2] bf e0 [2] bd e1 [2] a6 e7 [2] ba e0 [2] a6 cf }

  condition:
    any of them
}