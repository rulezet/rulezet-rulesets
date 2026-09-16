rule TTP_XOR_MULT_DOSStub_8900 {
  strings:
    $key_8900 = { dd 68 [2] a9 70 [2] ee 72 [2] a9 63 [2] e7 6f [2] eb 65 [2] fc 6e [2] e7 20 [2] da }

  condition:
    any of them
}