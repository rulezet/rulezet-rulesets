rule TTP_XOR_MULT_DOSStub_9bf9 {
  strings:
    $key_9bf9 = { cf 91 [2] bb 89 [2] fc 8b [2] bb 9a [2] f5 96 [2] f9 9c [2] ee 97 [2] f5 d9 [2] c8 }

  condition:
    any of them
}