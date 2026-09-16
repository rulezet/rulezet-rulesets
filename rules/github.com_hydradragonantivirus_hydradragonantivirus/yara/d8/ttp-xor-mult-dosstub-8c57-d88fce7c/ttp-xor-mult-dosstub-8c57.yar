rule TTP_XOR_MULT_DOSStub_8c57 {
  strings:
    $key_8c57 = { d8 3f [2] ac 27 [2] eb 25 [2] ac 34 [2] e2 38 [2] ee 32 [2] f9 39 [2] e2 77 [2] df }

  condition:
    any of them
}