rule TTP_XOR_MULT_DOSStub_894c {
  strings:
    $key_894c = { dd 24 [2] a9 3c [2] ee 3e [2] a9 2f [2] e7 23 [2] eb 29 [2] fc 22 [2] e7 6c [2] da }

  condition:
    any of them
}