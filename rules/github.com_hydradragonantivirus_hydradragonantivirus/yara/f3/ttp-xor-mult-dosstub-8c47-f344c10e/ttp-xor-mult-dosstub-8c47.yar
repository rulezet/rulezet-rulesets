rule TTP_XOR_MULT_DOSStub_8c47 {
  strings:
    $key_8c47 = { d8 2f [2] ac 37 [2] eb 35 [2] ac 24 [2] e2 28 [2] ee 22 [2] f9 29 [2] e2 67 [2] df }

  condition:
    any of them
}