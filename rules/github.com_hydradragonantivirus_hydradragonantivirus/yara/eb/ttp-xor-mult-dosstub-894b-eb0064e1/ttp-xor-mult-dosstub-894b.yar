rule TTP_XOR_MULT_DOSStub_894b {
  strings:
    $key_894b = { dd 23 [2] a9 3b [2] ee 39 [2] a9 28 [2] e7 24 [2] eb 2e [2] fc 25 [2] e7 6b [2] da }

  condition:
    any of them
}