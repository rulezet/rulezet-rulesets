rule TTP_XOR_MULT_DOSStub_89e6 {
  strings:
    $key_89e6 = { dd 8e [2] a9 96 [2] ee 94 [2] a9 85 [2] e7 89 [2] eb 83 [2] fc 88 [2] e7 c6 [2] da }

  condition:
    any of them
}