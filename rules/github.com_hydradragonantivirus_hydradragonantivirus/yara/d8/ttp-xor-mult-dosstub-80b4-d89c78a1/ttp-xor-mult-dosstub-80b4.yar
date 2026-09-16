rule TTP_XOR_MULT_DOSStub_80b4 {
  strings:
    $key_80b4 = { d4 dc [2] a0 c4 [2] e7 c6 [2] a0 d7 [2] ee db [2] e2 d1 [2] f5 da [2] ee 94 [2] d3 }

  condition:
    any of them
}