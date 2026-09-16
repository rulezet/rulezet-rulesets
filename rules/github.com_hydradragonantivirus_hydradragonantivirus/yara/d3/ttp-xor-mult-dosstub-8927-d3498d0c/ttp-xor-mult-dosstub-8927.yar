rule TTP_XOR_MULT_DOSStub_8927 {
  strings:
    $key_8927 = { dd 4f [2] a9 57 [2] ee 55 [2] a9 44 [2] e7 48 [2] eb 42 [2] fc 49 [2] e7 07 [2] da }

  condition:
    any of them
}