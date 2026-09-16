rule TTP_XOR_MULT_DOSStub_8c74 {
  strings:
    $key_8c74 = { d8 1c [2] ac 04 [2] eb 06 [2] ac 17 [2] e2 1b [2] ee 11 [2] f9 1a [2] e2 54 [2] df }

  condition:
    any of them
}