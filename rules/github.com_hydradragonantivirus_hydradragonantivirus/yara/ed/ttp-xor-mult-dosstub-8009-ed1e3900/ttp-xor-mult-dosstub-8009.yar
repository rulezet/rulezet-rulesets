rule TTP_XOR_MULT_DOSStub_8009 {
  strings:
    $key_8009 = { d4 61 [2] a0 79 [2] e7 7b [2] a0 6a [2] ee 66 [2] e2 6c [2] f5 67 [2] ee 29 [2] d3 }

  condition:
    any of them
}