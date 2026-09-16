rule TTP_XOR_MULT_DOSStub_9b60 {
  strings:
    $key_9b60 = { cf 08 [2] bb 10 [2] fc 12 [2] bb 03 [2] f5 0f [2] f9 05 [2] ee 0e [2] f5 40 [2] c8 }

  condition:
    any of them
}