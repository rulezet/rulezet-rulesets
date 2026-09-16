rule TTP_XOR_MULT_DOSStub_bfd4 {
  strings:
    $key_bfd4 = { eb bc [2] 9f a4 [2] d8 a6 [2] 9f b7 [2] d1 bb [2] dd b1 [2] ca ba [2] d1 f4 [2] ec }

  condition:
    any of them
}