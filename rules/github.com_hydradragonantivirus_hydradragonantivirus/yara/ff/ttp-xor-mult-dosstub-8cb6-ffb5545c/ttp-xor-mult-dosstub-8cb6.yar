rule TTP_XOR_MULT_DOSStub_8cb6 {
  strings:
    $key_8cb6 = { d8 de [2] ac c6 [2] eb c4 [2] ac d5 [2] e2 d9 [2] ee d3 [2] f9 d8 [2] e2 96 [2] df }

  condition:
    any of them
}