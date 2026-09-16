rule TTP_XOR_MULT_DOSStub_8cf5 {
  strings:
    $key_8cf5 = { d8 9d [2] ac 85 [2] eb 87 [2] ac 96 [2] e2 9a [2] ee 90 [2] f9 9b [2] e2 d5 [2] df }

  condition:
    any of them
}