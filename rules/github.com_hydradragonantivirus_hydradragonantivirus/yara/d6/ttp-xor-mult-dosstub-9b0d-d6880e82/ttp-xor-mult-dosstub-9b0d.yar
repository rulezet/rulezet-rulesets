rule TTP_XOR_MULT_DOSStub_9b0d {
  strings:
    $key_9b0d = { cf 65 [2] bb 7d [2] fc 7f [2] bb 6e [2] f5 62 [2] f9 68 [2] ee 63 [2] f5 2d [2] c8 }

  condition:
    any of them
}