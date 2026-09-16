rule TTP_XOR_MULT_DOSStub_8cb1 {
  strings:
    $key_8cb1 = { d8 d9 [2] ac c1 [2] eb c3 [2] ac d2 [2] e2 de [2] ee d4 [2] f9 df [2] e2 91 [2] df }

  condition:
    any of them
}