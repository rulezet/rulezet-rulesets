rule TTP_XOR_MULT_DOSStub_89fb {
  strings:
    $key_89fb = { dd 93 [2] a9 8b [2] ee 89 [2] a9 98 [2] e7 94 [2] eb 9e [2] fc 95 [2] e7 db [2] da }

  condition:
    any of them
}