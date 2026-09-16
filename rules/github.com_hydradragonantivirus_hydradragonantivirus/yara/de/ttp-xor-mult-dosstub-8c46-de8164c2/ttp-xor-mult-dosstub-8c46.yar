rule TTP_XOR_MULT_DOSStub_8c46 {
  strings:
    $key_8c46 = { d8 2e [2] ac 36 [2] eb 34 [2] ac 25 [2] e2 29 [2] ee 23 [2] f9 28 [2] e2 66 [2] df }

  condition:
    any of them
}