rule TTP_XOR_MULT_DOSStub_8c6e {
  strings:
    $key_8c6e = { d8 06 [2] ac 1e [2] eb 1c [2] ac 0d [2] e2 01 [2] ee 0b [2] f9 00 [2] e2 4e [2] df }

  condition:
    any of them
}