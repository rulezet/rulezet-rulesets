rule TTP_XOR_MULT_DOSStub_9b51 {
  strings:
    $key_9b51 = { cf 39 [2] bb 21 [2] fc 23 [2] bb 32 [2] f5 3e [2] f9 34 [2] ee 3f [2] f5 71 [2] c8 }

  condition:
    any of them
}