rule TTP_XOR_MULT_DOSStub_8c9c {
  strings:
    $key_8c9c = { d8 f4 [2] ac ec [2] eb ee [2] ac ff [2] e2 f3 [2] ee f9 [2] f9 f2 [2] e2 bc [2] df }

  condition:
    any of them
}