rule TTP_XOR_MULT_DOSStub_8c53 {
  strings:
    $key_8c53 = { d8 3b [2] ac 23 [2] eb 21 [2] ac 30 [2] e2 3c [2] ee 36 [2] f9 3d [2] e2 73 [2] df }

  condition:
    any of them
}