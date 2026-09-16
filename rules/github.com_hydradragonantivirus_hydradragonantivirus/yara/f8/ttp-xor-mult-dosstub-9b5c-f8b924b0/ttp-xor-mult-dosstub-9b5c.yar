rule TTP_XOR_MULT_DOSStub_9b5c {
  strings:
    $key_9b5c = { cf 34 [2] bb 2c [2] fc 2e [2] bb 3f [2] f5 33 [2] f9 39 [2] ee 32 [2] f5 7c [2] c8 }

  condition:
    any of them
}