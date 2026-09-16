rule TTP_XOR_MULT_DOSStub_8c42 {
  strings:
    $key_8c42 = { d8 2a [2] ac 32 [2] eb 30 [2] ac 21 [2] e2 2d [2] ee 27 [2] f9 2c [2] e2 62 [2] df }

  condition:
    any of them
}