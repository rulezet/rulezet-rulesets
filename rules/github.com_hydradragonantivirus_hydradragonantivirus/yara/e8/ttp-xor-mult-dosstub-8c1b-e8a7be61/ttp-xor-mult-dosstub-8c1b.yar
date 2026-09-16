rule TTP_XOR_MULT_DOSStub_8c1b {
  strings:
    $key_8c1b = { d8 73 [2] ac 6b [2] eb 69 [2] ac 78 [2] e2 74 [2] ee 7e [2] f9 75 [2] e2 3b [2] df }

  condition:
    any of them
}