rule TTP_XOR_MULT_DOSStub_9bf4 {
  strings:
    $key_9bf4 = { cf 9c [2] bb 84 [2] fc 86 [2] bb 97 [2] f5 9b [2] f9 91 [2] ee 9a [2] f5 d4 [2] c8 }

  condition:
    any of them
}