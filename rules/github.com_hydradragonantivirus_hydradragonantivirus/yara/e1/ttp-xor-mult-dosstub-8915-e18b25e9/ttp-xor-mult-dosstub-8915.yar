rule TTP_XOR_MULT_DOSStub_8915 {
  strings:
    $key_8915 = { dd 7d [2] a9 65 [2] ee 67 [2] a9 76 [2] e7 7a [2] eb 70 [2] fc 7b [2] e7 35 [2] da }

  condition:
    any of them
}