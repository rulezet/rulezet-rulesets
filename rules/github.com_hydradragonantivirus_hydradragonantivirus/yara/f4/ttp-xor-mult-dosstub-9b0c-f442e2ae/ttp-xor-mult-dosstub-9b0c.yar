rule TTP_XOR_MULT_DOSStub_9b0c {
  strings:
    $key_9b0c = { cf 64 [2] bb 7c [2] fc 7e [2] bb 6f [2] f5 63 [2] f9 69 [2] ee 62 [2] f5 2c [2] c8 }

  condition:
    any of them
}