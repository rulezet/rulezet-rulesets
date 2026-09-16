rule TTP_XOR_MULT_DOSStub_89c7 {
  strings:
    $key_89c7 = { dd af [2] a9 b7 [2] ee b5 [2] a9 a4 [2] e7 a8 [2] eb a2 [2] fc a9 [2] e7 e7 [2] da }

  condition:
    any of them
}