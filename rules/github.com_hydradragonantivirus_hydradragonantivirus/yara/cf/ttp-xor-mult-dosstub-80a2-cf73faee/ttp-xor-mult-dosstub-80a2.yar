rule TTP_XOR_MULT_DOSStub_80a2 {
  strings:
    $key_80a2 = { d4 ca [2] a0 d2 [2] e7 d0 [2] a0 c1 [2] ee cd [2] e2 c7 [2] f5 cc [2] ee 82 [2] d3 }

  condition:
    any of them
}