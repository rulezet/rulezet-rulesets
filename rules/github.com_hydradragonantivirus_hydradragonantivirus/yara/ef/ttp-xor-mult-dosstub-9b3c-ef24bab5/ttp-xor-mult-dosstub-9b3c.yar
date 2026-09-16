rule TTP_XOR_MULT_DOSStub_9b3c {
  strings:
    $key_9b3c = { cf 54 [2] bb 4c [2] fc 4e [2] bb 5f [2] f5 53 [2] f9 59 [2] ee 52 [2] f5 1c [2] c8 }

  condition:
    any of them
}