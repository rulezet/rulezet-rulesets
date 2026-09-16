rule TTP_XOR_MULT_DOSStub_80e3 {
  strings:
    $key_80e3 = { d4 8b [2] a0 93 [2] e7 91 [2] a0 80 [2] ee 8c [2] e2 86 [2] f5 8d [2] ee c3 [2] d3 }

  condition:
    any of them
}