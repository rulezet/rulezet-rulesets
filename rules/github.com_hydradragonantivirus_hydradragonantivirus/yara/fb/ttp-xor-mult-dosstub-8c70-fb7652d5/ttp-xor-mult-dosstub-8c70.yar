rule TTP_XOR_MULT_DOSStub_8c70 {
  strings:
    $key_8c70 = { d8 18 [2] ac 00 [2] eb 02 [2] ac 13 [2] e2 1f [2] ee 15 [2] f9 1e [2] e2 50 [2] df }

  condition:
    any of them
}