rule TTP_XOR_MULT_DOSStub_9b5d {
  strings:
    $key_9b5d = { cf 35 [2] bb 2d [2] fc 2f [2] bb 3e [2] f5 32 [2] f9 38 [2] ee 33 [2] f5 7d [2] c8 }

  condition:
    any of them
}