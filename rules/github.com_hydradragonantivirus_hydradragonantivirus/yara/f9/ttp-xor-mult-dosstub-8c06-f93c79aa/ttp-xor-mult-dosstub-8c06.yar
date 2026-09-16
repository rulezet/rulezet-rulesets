rule TTP_XOR_MULT_DOSStub_8c06 {
  strings:
    $key_8c06 = { d8 6e [2] ac 76 [2] eb 74 [2] ac 65 [2] e2 69 [2] ee 63 [2] f9 68 [2] e2 26 [2] df }

  condition:
    any of them
}