rule TTP_XOR_MULT_DOSStub_9b70 {
  strings:
    $key_9b70 = { cf 18 [2] bb 00 [2] fc 02 [2] bb 13 [2] f5 1f [2] f9 15 [2] ee 1e [2] f5 50 [2] c8 }

  condition:
    any of them
}