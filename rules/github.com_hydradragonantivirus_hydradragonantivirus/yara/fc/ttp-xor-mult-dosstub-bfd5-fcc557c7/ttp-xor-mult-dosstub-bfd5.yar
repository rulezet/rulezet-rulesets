rule TTP_XOR_MULT_DOSStub_bfd5 {
  strings:
    $key_bfd5 = { eb bd [2] 9f a5 [2] d8 a7 [2] 9f b6 [2] d1 ba [2] dd b0 [2] ca bb [2] d1 f5 [2] ec }

  condition:
    any of them
}