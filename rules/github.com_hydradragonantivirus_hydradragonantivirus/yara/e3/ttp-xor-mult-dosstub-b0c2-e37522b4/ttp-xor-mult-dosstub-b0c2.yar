rule TTP_XOR_MULT_DOSStub_b0c2 {
  strings:
    $key_b0c2 = { e4 aa [2] 90 b2 [2] d7 b0 [2] 90 a1 [2] de ad [2] d2 a7 [2] c5 ac [2] de e2 [2] e3 }

  condition:
    any of them
}