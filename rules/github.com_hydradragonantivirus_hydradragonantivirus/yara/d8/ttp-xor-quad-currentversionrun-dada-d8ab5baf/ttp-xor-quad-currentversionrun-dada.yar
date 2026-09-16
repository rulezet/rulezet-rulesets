rule TTP_XOR_QUAD_CurrentVersionRun_dada {
  strings:
    $key_dada = { 89 b5 [2] ad bb [2] 86 97 [2] a8 b5 [2] bc ae [2] b3 b4 [2] ad a9 [2] af a8 [2] b4 ae [2] a8 a9 [2] b4 86 }

  condition:
    any of them
}