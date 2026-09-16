rule TTP_XOR_MULT_DOSStub_8c4a {
  strings:
    $key_8c4a = { d8 22 [2] ac 3a [2] eb 38 [2] ac 29 [2] e2 25 [2] ee 2f [2] f9 24 [2] e2 6a [2] df }

  condition:
    any of them
}