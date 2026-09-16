rule TTP_XOR_MULT_DOSStub_9b00 {
  strings:
    $key_9b00 = { cf 68 [2] bb 70 [2] fc 72 [2] bb 63 [2] f5 6f [2] f9 65 [2] ee 6e [2] f5 20 [2] c8 }

  condition:
    any of them
}