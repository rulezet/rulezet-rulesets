rule TTP_XOR_MULT_DOSStub_8028 {
  strings:
    $key_8028 = { d4 40 [2] a0 58 [2] e7 5a [2] a0 4b [2] ee 47 [2] e2 4d [2] f5 46 [2] ee 08 [2] d3 }

  condition:
    any of them
}