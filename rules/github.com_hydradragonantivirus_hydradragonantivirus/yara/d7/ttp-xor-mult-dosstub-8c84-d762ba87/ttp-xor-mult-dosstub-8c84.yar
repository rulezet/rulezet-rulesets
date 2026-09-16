rule TTP_XOR_MULT_DOSStub_8c84 {
  strings:
    $key_8c84 = { d8 ec [2] ac f4 [2] eb f6 [2] ac e7 [2] e2 eb [2] ee e1 [2] f9 ea [2] e2 a4 [2] df }

  condition:
    any of them
}