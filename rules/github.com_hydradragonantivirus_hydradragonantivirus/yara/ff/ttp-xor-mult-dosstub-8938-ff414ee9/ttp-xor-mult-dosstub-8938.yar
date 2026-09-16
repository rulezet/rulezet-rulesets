rule TTP_XOR_MULT_DOSStub_8938 {
  strings:
    $key_8938 = { dd 50 [2] a9 48 [2] ee 4a [2] a9 5b [2] e7 57 [2] eb 5d [2] fc 56 [2] e7 18 [2] da }

  condition:
    any of them
}