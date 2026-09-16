rule TTP_XOR_MULT_DOSStub_8c73 {
  strings:
    $key_8c73 = { d8 1b [2] ac 03 [2] eb 01 [2] ac 10 [2] e2 1c [2] ee 16 [2] f9 1d [2] e2 53 [2] df }

  condition:
    any of them
}