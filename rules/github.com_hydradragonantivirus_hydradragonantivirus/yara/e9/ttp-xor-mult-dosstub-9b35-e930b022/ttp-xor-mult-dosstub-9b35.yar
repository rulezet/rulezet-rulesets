rule TTP_XOR_MULT_DOSStub_9b35 {
  strings:
    $key_9b35 = { cf 5d [2] bb 45 [2] fc 47 [2] bb 56 [2] f5 5a [2] f9 50 [2] ee 5b [2] f5 15 [2] c8 }

  condition:
    any of them
}