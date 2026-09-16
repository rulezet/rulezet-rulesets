rule TTP_XOR_MULT_DOSStub_892e {
  strings:
    $key_892e = { dd 46 [2] a9 5e [2] ee 5c [2] a9 4d [2] e7 41 [2] eb 4b [2] fc 40 [2] e7 0e [2] da }

  condition:
    any of them
}