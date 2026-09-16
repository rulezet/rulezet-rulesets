rule TTP_XOR_MULT_DOSStub_9b64 {
  strings:
    $key_9b64 = { cf 0c [2] bb 14 [2] fc 16 [2] bb 07 [2] f5 0b [2] f9 01 [2] ee 0a [2] f5 44 [2] c8 }

  condition:
    any of them
}