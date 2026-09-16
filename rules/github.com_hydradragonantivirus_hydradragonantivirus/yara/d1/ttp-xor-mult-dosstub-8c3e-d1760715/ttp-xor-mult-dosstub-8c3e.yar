rule TTP_XOR_MULT_DOSStub_8c3e {
  strings:
    $key_8c3e = { d8 56 [2] ac 4e [2] eb 4c [2] ac 5d [2] e2 51 [2] ee 5b [2] f9 50 [2] e2 1e [2] df }

  condition:
    any of them
}