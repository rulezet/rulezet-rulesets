rule TTP_XOR_MULT_DOSStub_80e0 {
  strings:
    $key_80e0 = { d4 88 [2] a0 90 [2] e7 92 [2] a0 83 [2] ee 8f [2] e2 85 [2] f5 8e [2] ee c0 [2] d3 }

  condition:
    any of them
}