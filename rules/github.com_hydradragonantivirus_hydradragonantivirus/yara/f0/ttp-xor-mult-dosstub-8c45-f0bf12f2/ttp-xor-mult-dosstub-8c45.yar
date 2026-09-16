rule TTP_XOR_MULT_DOSStub_8c45 {
  strings:
    $key_8c45 = { d8 2d [2] ac 35 [2] eb 37 [2] ac 26 [2] e2 2a [2] ee 20 [2] f9 2b [2] e2 65 [2] df }

  condition:
    any of them
}