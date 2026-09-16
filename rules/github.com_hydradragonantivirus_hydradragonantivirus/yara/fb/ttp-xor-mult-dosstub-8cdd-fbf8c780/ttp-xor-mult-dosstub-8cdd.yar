rule TTP_XOR_MULT_DOSStub_8cdd {
  strings:
    $key_8cdd = { d8 b5 [2] ac ad [2] eb af [2] ac be [2] e2 b2 [2] ee b8 [2] f9 b3 [2] e2 fd [2] df }

  condition:
    any of them
}