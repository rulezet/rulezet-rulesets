rule TTP_XOR_MULT_DOSStub_80aa {
  strings:
    $key_80aa = { d4 c2 [2] a0 da [2] e7 d8 [2] a0 c9 [2] ee c5 [2] e2 cf [2] f5 c4 [2] ee 8a [2] d3 }

  condition:
    any of them
}