rule TTP_XOR_MULT_DOSStub_8918 {
  strings:
    $key_8918 = { dd 70 [2] a9 68 [2] ee 6a [2] a9 7b [2] e7 77 [2] eb 7d [2] fc 76 [2] e7 38 [2] da }

  condition:
    any of them
}