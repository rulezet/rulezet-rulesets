rule TTP_XOR_MULT_DOSStub_8079 {
  strings:
    $key_8079 = { d4 11 [2] a0 09 [2] e7 0b [2] a0 1a [2] ee 16 [2] e2 1c [2] f5 17 [2] ee 59 [2] d3 }

  condition:
    any of them
}