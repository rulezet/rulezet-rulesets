rule TTP_XOR_MULT_DOSStub_8920 {
  strings:
    $key_8920 = { dd 48 [2] a9 50 [2] ee 52 [2] a9 43 [2] e7 4f [2] eb 45 [2] fc 4e [2] e7 00 [2] da }

  condition:
    any of them
}