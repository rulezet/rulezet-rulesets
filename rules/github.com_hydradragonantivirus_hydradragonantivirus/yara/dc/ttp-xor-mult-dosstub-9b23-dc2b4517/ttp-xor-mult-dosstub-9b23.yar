rule TTP_XOR_MULT_DOSStub_9b23 {
  strings:
    $key_9b23 = { cf 4b [2] bb 53 [2] fc 51 [2] bb 40 [2] f5 4c [2] f9 46 [2] ee 4d [2] f5 03 [2] c8 }

  condition:
    any of them
}