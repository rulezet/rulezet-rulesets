rule TTP_XOR_MULT_DOSStub_9bf6 {
  strings:
    $key_9bf6 = { cf 9e [2] bb 86 [2] fc 84 [2] bb 95 [2] f5 99 [2] f9 93 [2] ee 98 [2] f5 d6 [2] c8 }

  condition:
    any of them
}