rule TTP_XOR_MULT_DOSStub_8942 {
  strings:
    $key_8942 = { dd 2a [2] a9 32 [2] ee 30 [2] a9 21 [2] e7 2d [2] eb 27 [2] fc 2c [2] e7 62 [2] da }

  condition:
    any of them
}