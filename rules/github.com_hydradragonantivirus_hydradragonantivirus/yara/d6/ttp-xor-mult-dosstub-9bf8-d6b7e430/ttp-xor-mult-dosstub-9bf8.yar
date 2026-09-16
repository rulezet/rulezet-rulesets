rule TTP_XOR_MULT_DOSStub_9bf8 {
  strings:
    $key_9bf8 = { cf 90 [2] bb 88 [2] fc 8a [2] bb 9b [2] f5 97 [2] f9 9d [2] ee 96 [2] f5 d8 [2] c8 }

  condition:
    any of them
}