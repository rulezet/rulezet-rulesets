rule TTP_XOR_MULT_DOSStub_8c8d {
  strings:
    $key_8c8d = { d8 e5 [2] ac fd [2] eb ff [2] ac ee [2] e2 e2 [2] ee e8 [2] f9 e3 [2] e2 ad [2] df }

  condition:
    any of them
}