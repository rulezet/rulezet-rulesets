rule TTP_XOR_MULT_DOSStub_b5d8 {
  strings:
    $key_b5d8 = { e1 b0 [2] 95 a8 [2] d2 aa [2] 95 bb [2] db b7 [2] d7 bd [2] c0 b6 [2] db f8 [2] e6 }

  condition:
    any of them
}