rule TTP_XOR_MULT_DOSStub_8ce0 {
  strings:
    $key_8ce0 = { d8 88 [2] ac 90 [2] eb 92 [2] ac 83 [2] e2 8f [2] ee 85 [2] f9 8e [2] e2 c0 [2] df }

  condition:
    any of them
}