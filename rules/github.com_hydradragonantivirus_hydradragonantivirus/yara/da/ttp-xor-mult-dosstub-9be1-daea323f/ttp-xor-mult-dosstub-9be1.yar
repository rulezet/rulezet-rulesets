rule TTP_XOR_MULT_DOSStub_9be1 {
  strings:
    $key_9be1 = { cf 89 [2] bb 91 [2] fc 93 [2] bb 82 [2] f5 8e [2] f9 84 [2] ee 8f [2] f5 c1 [2] c8 }

  condition:
    any of them
}