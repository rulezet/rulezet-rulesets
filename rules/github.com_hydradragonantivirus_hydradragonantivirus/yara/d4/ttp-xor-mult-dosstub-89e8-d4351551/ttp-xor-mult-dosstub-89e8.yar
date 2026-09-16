rule TTP_XOR_MULT_DOSStub_89e8 {
  strings:
    $key_89e8 = { dd 80 [2] a9 98 [2] ee 9a [2] a9 8b [2] e7 87 [2] eb 8d [2] fc 86 [2] e7 c8 [2] da }

  condition:
    any of them
}