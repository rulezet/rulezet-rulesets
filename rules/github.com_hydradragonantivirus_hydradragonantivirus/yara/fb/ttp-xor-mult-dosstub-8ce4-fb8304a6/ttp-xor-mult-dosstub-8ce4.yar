rule TTP_XOR_MULT_DOSStub_8ce4 {
  strings:
    $key_8ce4 = { d8 8c [2] ac 94 [2] eb 96 [2] ac 87 [2] e2 8b [2] ee 81 [2] f9 8a [2] e2 c4 [2] df }

  condition:
    any of them
}