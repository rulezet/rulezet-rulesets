rule TTP_XOR_MULT_DOSStub_8ce3 {
  strings:
    $key_8ce3 = { d8 8b [2] ac 93 [2] eb 91 [2] ac 80 [2] e2 8c [2] ee 86 [2] f9 8d [2] e2 c3 [2] df }

  condition:
    any of them
}