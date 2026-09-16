rule TTP_XOR_MULT_DOSStub_8002 {
  strings:
    $key_8002 = { d4 6a [2] a0 72 [2] e7 70 [2] a0 61 [2] ee 6d [2] e2 67 [2] f5 6c [2] ee 22 [2] d3 }

  condition:
    any of them
}