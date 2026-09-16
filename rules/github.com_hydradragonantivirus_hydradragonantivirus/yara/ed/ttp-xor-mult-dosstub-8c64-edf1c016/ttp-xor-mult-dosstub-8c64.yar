rule TTP_XOR_MULT_DOSStub_8c64 {
  strings:
    $key_8c64 = { d8 0c [2] ac 14 [2] eb 16 [2] ac 07 [2] e2 0b [2] ee 01 [2] f9 0a [2] e2 44 [2] df }

  condition:
    any of them
}