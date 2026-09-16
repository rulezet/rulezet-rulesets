rule TTP_XOR_MULT_DOSStub_80b2 {
  strings:
    $key_80b2 = { d4 da [2] a0 c2 [2] e7 c0 [2] a0 d1 [2] ee dd [2] e2 d7 [2] f5 dc [2] ee 92 [2] d3 }

  condition:
    any of them
}