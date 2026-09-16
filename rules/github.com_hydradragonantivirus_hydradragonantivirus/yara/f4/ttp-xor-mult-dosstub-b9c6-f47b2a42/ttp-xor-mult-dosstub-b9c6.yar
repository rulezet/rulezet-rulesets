rule TTP_XOR_MULT_DOSStub_b9c6 {
  strings:
    $key_b9c6 = { ed ae [2] 99 b6 [2] de b4 [2] 99 a5 [2] d7 a9 [2] db a3 [2] cc a8 [2] d7 e6 [2] ea }

  condition:
    any of them
}