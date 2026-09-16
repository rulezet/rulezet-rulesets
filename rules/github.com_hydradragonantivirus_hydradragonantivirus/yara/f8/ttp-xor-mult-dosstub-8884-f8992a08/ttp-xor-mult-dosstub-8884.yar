rule TTP_XOR_MULT_DOSStub_8884 {
  strings:
    $key_8884 = { dc ec [2] a8 f4 [2] ef f6 [2] a8 e7 [2] e6 eb [2] ea e1 [2] fd ea [2] e6 a4 [2] db }

  condition:
    any of them
}