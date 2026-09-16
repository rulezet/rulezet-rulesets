rule TTP_XOR_MULT_DOSStub_893c {
  strings:
    $key_893c = { dd 54 [2] a9 4c [2] ee 4e [2] a9 5f [2] e7 53 [2] eb 59 [2] fc 52 [2] e7 1c [2] da }

  condition:
    any of them
}