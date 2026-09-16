rule TTP_XOR_MULT_DOSStub_8ab6 {
  strings:
    $key_8ab6 = { de de [2] aa c6 [2] ed c4 [2] aa d5 [2] e4 d9 [2] e8 d3 [2] ff d8 [2] e4 96 [2] d9 }

  condition:
    any of them
}