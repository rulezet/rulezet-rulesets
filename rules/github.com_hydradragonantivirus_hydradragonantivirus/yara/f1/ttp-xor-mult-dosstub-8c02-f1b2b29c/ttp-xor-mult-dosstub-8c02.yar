rule TTP_XOR_MULT_DOSStub_8c02 {
  strings:
    $key_8c02 = { d8 6a [2] ac 72 [2] eb 70 [2] ac 61 [2] e2 6d [2] ee 67 [2] f9 6c [2] e2 22 [2] df }

  condition:
    any of them
}