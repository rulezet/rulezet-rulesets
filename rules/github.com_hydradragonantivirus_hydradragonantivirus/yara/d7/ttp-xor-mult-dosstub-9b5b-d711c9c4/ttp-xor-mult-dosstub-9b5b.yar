rule TTP_XOR_MULT_DOSStub_9b5b {
  strings:
    $key_9b5b = { cf 33 [2] bb 2b [2] fc 29 [2] bb 38 [2] f5 34 [2] f9 3e [2] ee 35 [2] f5 7b [2] c8 }

  condition:
    any of them
}