rule TTP_XOR_MULT_DOSStub_896a {
  strings:
    $key_896a = { dd 02 [2] a9 1a [2] ee 18 [2] a9 09 [2] e7 05 [2] eb 0f [2] fc 04 [2] e7 4a [2] da }

  condition:
    any of them
}