rule TTP_XOR_MULT_DOSStub_8c24 {
  strings:
    $key_8c24 = { d8 4c [2] ac 54 [2] eb 56 [2] ac 47 [2] e2 4b [2] ee 41 [2] f9 4a [2] e2 04 [2] df }

  condition:
    any of them
}