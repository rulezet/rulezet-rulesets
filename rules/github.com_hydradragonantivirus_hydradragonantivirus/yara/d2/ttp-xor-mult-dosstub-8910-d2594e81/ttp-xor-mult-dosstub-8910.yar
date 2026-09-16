rule TTP_XOR_MULT_DOSStub_8910 {
  strings:
    $key_8910 = { dd 78 [2] a9 60 [2] ee 62 [2] a9 73 [2] e7 7f [2] eb 75 [2] fc 7e [2] e7 30 [2] da }

  condition:
    any of them
}