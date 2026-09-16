rule TTP_XOR_MULT_DOSStub_8c41 {
  strings:
    $key_8c41 = { d8 29 [2] ac 31 [2] eb 33 [2] ac 22 [2] e2 2e [2] ee 24 [2] f9 2f [2] e2 61 [2] df }

  condition:
    any of them
}