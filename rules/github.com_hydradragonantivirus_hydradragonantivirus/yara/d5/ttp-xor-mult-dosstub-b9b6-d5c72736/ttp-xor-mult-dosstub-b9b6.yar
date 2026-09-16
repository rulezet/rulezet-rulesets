rule TTP_XOR_MULT_DOSStub_b9b6 {
  strings:
    $key_b9b6 = { ed de [2] 99 c6 [2] de c4 [2] 99 d5 [2] d7 d9 [2] db d3 [2] cc d8 [2] d7 96 [2] ea }

  condition:
    any of them
}