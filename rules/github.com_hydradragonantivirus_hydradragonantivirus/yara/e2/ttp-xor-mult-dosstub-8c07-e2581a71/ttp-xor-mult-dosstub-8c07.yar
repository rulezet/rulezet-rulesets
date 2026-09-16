rule TTP_XOR_MULT_DOSStub_8c07 {
  strings:
    $key_8c07 = { d8 6f [2] ac 77 [2] eb 75 [2] ac 64 [2] e2 68 [2] ee 62 [2] f9 69 [2] e2 27 [2] df }

  condition:
    any of them
}