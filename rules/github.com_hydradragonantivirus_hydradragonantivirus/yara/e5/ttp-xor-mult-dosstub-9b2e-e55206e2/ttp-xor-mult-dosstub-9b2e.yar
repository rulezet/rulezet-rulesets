rule TTP_XOR_MULT_DOSStub_9b2e {
  strings:
    $key_9b2e = { cf 46 [2] bb 5e [2] fc 5c [2] bb 4d [2] f5 41 [2] f9 4b [2] ee 40 [2] f5 0e [2] c8 }

  condition:
    any of them
}