rule TTP_XOR_MULT_DOSStub_894a {
  strings:
    $key_894a = { dd 22 [2] a9 3a [2] ee 38 [2] a9 29 [2] e7 25 [2] eb 2f [2] fc 24 [2] e7 6a [2] da }

  condition:
    any of them
}