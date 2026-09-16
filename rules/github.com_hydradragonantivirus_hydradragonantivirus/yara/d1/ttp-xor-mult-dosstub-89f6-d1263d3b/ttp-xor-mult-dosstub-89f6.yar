rule TTP_XOR_MULT_DOSStub_89f6 {
  strings:
    $key_89f6 = { dd 9e [2] a9 86 [2] ee 84 [2] a9 95 [2] e7 99 [2] eb 93 [2] fc 98 [2] e7 d6 [2] da }

  condition:
    any of them
}