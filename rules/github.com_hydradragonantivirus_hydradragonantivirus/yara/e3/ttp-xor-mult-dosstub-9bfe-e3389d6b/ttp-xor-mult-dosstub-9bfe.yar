rule TTP_XOR_MULT_DOSStub_9bfe {
  strings:
    $key_9bfe = { cf 96 [2] bb 8e [2] fc 8c [2] bb 9d [2] f5 91 [2] f9 9b [2] ee 90 [2] f5 de [2] c8 }

  condition:
    any of them
}