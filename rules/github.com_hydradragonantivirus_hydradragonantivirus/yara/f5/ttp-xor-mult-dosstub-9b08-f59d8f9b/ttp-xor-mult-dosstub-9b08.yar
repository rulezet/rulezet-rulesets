rule TTP_XOR_MULT_DOSStub_9b08 {
  strings:
    $key_9b08 = { cf 60 [2] bb 78 [2] fc 7a [2] bb 6b [2] f5 67 [2] f9 6d [2] ee 66 [2] f5 28 [2] c8 }

  condition:
    any of them
}