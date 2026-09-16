rule TTP_XOR_MULT_DOSStub_9b74 {
  strings:
    $key_9b74 = { cf 1c [2] bb 04 [2] fc 06 [2] bb 17 [2] f5 1b [2] f9 11 [2] ee 1a [2] f5 54 [2] c8 }

  condition:
    any of them
}