rule TTP_XOR_MULT_DOSStub_80a9 {
  strings:
    $key_80a9 = { d4 c1 [2] a0 d9 [2] e7 db [2] a0 ca [2] ee c6 [2] e2 cc [2] f5 c7 [2] ee 89 [2] d3 }

  condition:
    any of them
}