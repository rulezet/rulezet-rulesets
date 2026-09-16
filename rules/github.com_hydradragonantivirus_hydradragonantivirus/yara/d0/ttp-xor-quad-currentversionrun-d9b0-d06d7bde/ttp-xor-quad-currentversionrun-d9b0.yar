rule TTP_XOR_QUAD_CurrentVersionRun_d9b0 {
  strings:
    $key_d9b0 = { 8a df [2] ae d1 [2] 85 fd [2] ab df [2] bf c4 [2] b0 de [2] ae c3 [2] ac c2 [2] b7 c4 [2] ab c3 [2] b7 ec }

  condition:
    any of them
}