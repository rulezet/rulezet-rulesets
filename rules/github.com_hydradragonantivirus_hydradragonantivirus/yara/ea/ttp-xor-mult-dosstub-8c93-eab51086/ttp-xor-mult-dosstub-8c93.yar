rule TTP_XOR_MULT_DOSStub_8c93 {
  strings:
    $key_8c93 = { d8 fb [2] ac e3 [2] eb e1 [2] ac f0 [2] e2 fc [2] ee f6 [2] f9 fd [2] e2 b3 [2] df }

  condition:
    any of them
}