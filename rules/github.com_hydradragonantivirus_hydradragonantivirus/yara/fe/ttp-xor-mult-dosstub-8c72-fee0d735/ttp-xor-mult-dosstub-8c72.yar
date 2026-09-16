rule TTP_XOR_MULT_DOSStub_8c72 {
  strings:
    $key_8c72 = { d8 1a [2] ac 02 [2] eb 00 [2] ac 11 [2] e2 1d [2] ee 17 [2] f9 1c [2] e2 52 [2] df }

  condition:
    any of them
}