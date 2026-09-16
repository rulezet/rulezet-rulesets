rule TTP_XOR_MULT_DOSStub_8cf9 {
  strings:
    $key_8cf9 = { d8 91 [2] ac 89 [2] eb 8b [2] ac 9a [2] e2 96 [2] ee 9c [2] f9 97 [2] e2 d9 [2] df }

  condition:
    any of them
}