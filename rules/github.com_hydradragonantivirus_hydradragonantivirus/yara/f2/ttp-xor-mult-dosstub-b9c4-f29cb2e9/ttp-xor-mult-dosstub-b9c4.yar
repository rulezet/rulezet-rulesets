rule TTP_XOR_MULT_DOSStub_b9c4 {
  strings:
    $key_b9c4 = { ed ac [2] 99 b4 [2] de b6 [2] 99 a7 [2] d7 ab [2] db a1 [2] cc aa [2] d7 e4 [2] ea }

  condition:
    any of them
}