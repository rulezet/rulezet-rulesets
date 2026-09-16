rule TTP_XOR_MULT_DOSStub_8c6d {
  strings:
    $key_8c6d = { d8 05 [2] ac 1d [2] eb 1f [2] ac 0e [2] e2 02 [2] ee 08 [2] f9 03 [2] e2 4d [2] df }

  condition:
    any of them
}