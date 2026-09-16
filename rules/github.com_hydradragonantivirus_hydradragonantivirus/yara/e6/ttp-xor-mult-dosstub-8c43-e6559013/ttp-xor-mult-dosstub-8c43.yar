rule TTP_XOR_MULT_DOSStub_8c43 {
  strings:
    $key_8c43 = { d8 2b [2] ac 33 [2] eb 31 [2] ac 20 [2] e2 2c [2] ee 26 [2] f9 2d [2] e2 63 [2] df }

  condition:
    any of them
}