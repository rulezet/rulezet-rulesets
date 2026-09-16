rule TTP_XOR_MULT_DOSStub_9b71 {
  strings:
    $key_9b71 = { cf 19 [2] bb 01 [2] fc 03 [2] bb 12 [2] f5 1e [2] f9 14 [2] ee 1f [2] f5 51 [2] c8 }

  condition:
    any of them
}