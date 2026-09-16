rule TTP_XOR_MULT_DOSStub_80a8 {
  strings:
    $key_80a8 = { d4 c0 [2] a0 d8 [2] e7 da [2] a0 cb [2] ee c7 [2] e2 cd [2] f5 c6 [2] ee 88 [2] d3 }

  condition:
    any of them
}