rule TTP_XOR_MULT_DOSStub_9b24 {
  strings:
    $key_9b24 = { cf 4c [2] bb 54 [2] fc 56 [2] bb 47 [2] f5 4b [2] f9 41 [2] ee 4a [2] f5 04 [2] c8 }

  condition:
    any of them
}