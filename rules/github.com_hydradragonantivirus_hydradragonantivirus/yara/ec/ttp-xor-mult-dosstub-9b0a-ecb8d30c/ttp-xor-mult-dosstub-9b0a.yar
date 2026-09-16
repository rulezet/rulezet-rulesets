rule TTP_XOR_MULT_DOSStub_9b0a {
  strings:
    $key_9b0a = { cf 62 [2] bb 7a [2] fc 78 [2] bb 69 [2] f5 65 [2] f9 6f [2] ee 64 [2] f5 2a [2] c8 }

  condition:
    any of them
}