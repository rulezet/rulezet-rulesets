rule TTP_XOR_MULT_DOSStub_8062 {
  strings:
    $key_8062 = { d4 0a [2] a0 12 [2] e7 10 [2] a0 01 [2] ee 0d [2] e2 07 [2] f5 0c [2] ee 42 [2] d3 }

  condition:
    any of them
}