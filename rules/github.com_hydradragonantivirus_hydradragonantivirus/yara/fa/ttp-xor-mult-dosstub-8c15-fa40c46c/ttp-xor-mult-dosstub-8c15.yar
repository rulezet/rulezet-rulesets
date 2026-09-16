rule TTP_XOR_MULT_DOSStub_8c15 {
  strings:
    $key_8c15 = { d8 7d [2] ac 65 [2] eb 67 [2] ac 76 [2] e2 7a [2] ee 70 [2] f9 7b [2] e2 35 [2] df }

  condition:
    any of them
}