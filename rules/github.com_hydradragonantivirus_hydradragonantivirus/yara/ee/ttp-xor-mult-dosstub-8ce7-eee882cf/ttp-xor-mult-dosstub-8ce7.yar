rule TTP_XOR_MULT_DOSStub_8ce7 {
  strings:
    $key_8ce7 = { d8 8f [2] ac 97 [2] eb 95 [2] ac 84 [2] e2 88 [2] ee 82 [2] f9 89 [2] e2 c7 [2] df }

  condition:
    any of them
}