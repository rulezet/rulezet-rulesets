rule TTP_XOR_MULT_DOSStub_9be4 {
  strings:
    $key_9be4 = { cf 8c [2] bb 94 [2] fc 96 [2] bb 87 [2] f5 8b [2] f9 81 [2] ee 8a [2] f5 c4 [2] c8 }

  condition:
    any of them
}