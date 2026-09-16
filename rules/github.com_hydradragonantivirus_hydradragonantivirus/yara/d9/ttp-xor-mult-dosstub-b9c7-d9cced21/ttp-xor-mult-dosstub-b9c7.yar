rule TTP_XOR_MULT_DOSStub_b9c7 {
  strings:
    $key_b9c7 = { ed af [2] 99 b7 [2] de b5 [2] 99 a4 [2] d7 a8 [2] db a2 [2] cc a9 [2] d7 e7 [2] ea }

  condition:
    any of them
}