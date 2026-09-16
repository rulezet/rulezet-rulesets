rule TTP_XOR_MULT_DOSStub_8c65 {
  strings:
    $key_8c65 = { d8 0d [2] ac 15 [2] eb 17 [2] ac 06 [2] e2 0a [2] ee 00 [2] f9 0b [2] e2 45 [2] df }

  condition:
    any of them
}