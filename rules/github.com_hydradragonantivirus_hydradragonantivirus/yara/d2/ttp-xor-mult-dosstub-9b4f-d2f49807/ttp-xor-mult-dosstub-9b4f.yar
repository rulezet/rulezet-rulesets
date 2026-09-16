rule TTP_XOR_MULT_DOSStub_9b4f {
  strings:
    $key_9b4f = { cf 27 [2] bb 3f [2] fc 3d [2] bb 2c [2] f5 20 [2] f9 2a [2] ee 21 [2] f5 6f [2] c8 }

  condition:
    any of them
}