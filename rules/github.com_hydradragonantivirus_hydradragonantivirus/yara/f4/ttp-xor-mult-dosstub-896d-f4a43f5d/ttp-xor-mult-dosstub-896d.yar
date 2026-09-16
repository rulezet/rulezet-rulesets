rule TTP_XOR_MULT_DOSStub_896d {
  strings:
    $key_896d = { dd 05 [2] a9 1d [2] ee 1f [2] a9 0e [2] e7 02 [2] eb 08 [2] fc 03 [2] e7 4d [2] da }

  condition:
    any of them
}