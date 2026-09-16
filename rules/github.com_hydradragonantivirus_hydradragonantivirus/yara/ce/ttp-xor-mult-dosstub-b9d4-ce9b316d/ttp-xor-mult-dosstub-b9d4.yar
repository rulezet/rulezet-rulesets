rule TTP_XOR_MULT_DOSStub_b9d4 {
  strings:
    $key_b9d4 = { ed bc [2] 99 a4 [2] de a6 [2] 99 b7 [2] d7 bb [2] db b1 [2] cc ba [2] d7 f4 [2] ea }

  condition:
    any of them
}