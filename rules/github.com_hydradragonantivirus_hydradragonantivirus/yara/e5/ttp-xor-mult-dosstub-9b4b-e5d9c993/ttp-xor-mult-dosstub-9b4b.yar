rule TTP_XOR_MULT_DOSStub_9b4b {
  strings:
    $key_9b4b = { cf 23 [2] bb 3b [2] fc 39 [2] bb 28 [2] f5 24 [2] f9 2e [2] ee 25 [2] f5 6b [2] c8 }

  condition:
    any of them
}