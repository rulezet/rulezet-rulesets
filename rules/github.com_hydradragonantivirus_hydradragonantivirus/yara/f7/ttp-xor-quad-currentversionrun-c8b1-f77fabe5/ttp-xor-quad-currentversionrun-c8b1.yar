rule TTP_XOR_QUAD_CurrentVersionRun_c8b1 {
  strings:
    $key_c8b1 = { 9b de [2] bf d0 [2] 94 fc [2] ba de [2] ae c5 [2] a1 df [2] bf c2 [2] bd c3 [2] a6 c5 [2] ba c2 [2] a6 ed }

  condition:
    any of them
}