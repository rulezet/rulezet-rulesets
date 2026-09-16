rule TTP_XOR_MULT_DOSStub_8cf1 {
  strings:
    $key_8cf1 = { d8 99 [2] ac 81 [2] eb 83 [2] ac 92 [2] e2 9e [2] ee 94 [2] f9 9f [2] e2 d1 [2] df }

  condition:
    any of them
}