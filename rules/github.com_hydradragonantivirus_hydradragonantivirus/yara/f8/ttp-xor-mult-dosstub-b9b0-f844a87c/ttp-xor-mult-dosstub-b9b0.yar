rule TTP_XOR_MULT_DOSStub_b9b0 {
  strings:
    $key_b9b0 = { ed d8 [2] 99 c0 [2] de c2 [2] 99 d3 [2] d7 df [2] db d5 [2] cc de [2] d7 90 [2] ea }

  condition:
    any of them
}