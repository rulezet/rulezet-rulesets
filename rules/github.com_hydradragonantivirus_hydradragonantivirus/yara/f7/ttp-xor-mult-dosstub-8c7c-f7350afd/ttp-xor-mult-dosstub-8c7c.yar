rule TTP_XOR_MULT_DOSStub_8c7c {
  strings:
    $key_8c7c = { d8 14 [2] ac 0c [2] eb 0e [2] ac 1f [2] e2 13 [2] ee 19 [2] f9 12 [2] e2 5c [2] df }

  condition:
    any of them
}