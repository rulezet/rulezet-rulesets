rule TTP_XOR_MULT_DOSStub_9bfb {
  strings:
    $key_9bfb = { cf 93 [2] bb 8b [2] fc 89 [2] bb 98 [2] f5 94 [2] f9 9e [2] ee 95 [2] f5 db [2] c8 }

  condition:
    any of them
}