rule TTP_XOR_MULT_DOSStub_bcb6 {
  strings:
    $key_bcb6 = { e8 de [2] 9c c6 [2] db c4 [2] 9c d5 [2] d2 d9 [2] de d3 [2] c9 d8 [2] d2 96 [2] ef }

  condition:
    any of them
}