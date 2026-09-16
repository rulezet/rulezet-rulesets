rule TTP_XOR_MULT_DOSStub_893a {
  strings:
    $key_893a = { dd 52 [2] a9 4a [2] ee 48 [2] a9 59 [2] e7 55 [2] eb 5f [2] fc 54 [2] e7 1a [2] da }

  condition:
    any of them
}