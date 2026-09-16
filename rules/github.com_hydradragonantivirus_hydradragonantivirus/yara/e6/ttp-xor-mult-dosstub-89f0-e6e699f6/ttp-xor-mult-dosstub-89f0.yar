rule TTP_XOR_MULT_DOSStub_89f0 {
  strings:
    $key_89f0 = { dd 98 [2] a9 80 [2] ee 82 [2] a9 93 [2] e7 9f [2] eb 95 [2] fc 9e [2] e7 d0 [2] da }

  condition:
    any of them
}