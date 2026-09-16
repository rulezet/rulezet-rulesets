rule TTP_XOR_MULT_DOSStub_8c1c {
  strings:
    $key_8c1c = { d8 74 [2] ac 6c [2] eb 6e [2] ac 7f [2] e2 73 [2] ee 79 [2] f9 72 [2] e2 3c [2] df }

  condition:
    any of them
}