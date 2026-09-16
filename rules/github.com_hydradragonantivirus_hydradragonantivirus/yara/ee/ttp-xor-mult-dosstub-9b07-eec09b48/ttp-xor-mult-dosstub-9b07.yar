rule TTP_XOR_MULT_DOSStub_9b07 {
  strings:
    $key_9b07 = { cf 6f [2] bb 77 [2] fc 75 [2] bb 64 [2] f5 68 [2] f9 62 [2] ee 69 [2] f5 27 [2] c8 }

  condition:
    any of them
}