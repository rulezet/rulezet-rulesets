rule TTP_XOR_MULT_DOSStub_8026 {
  strings:
    $key_8026 = { d4 4e [2] a0 56 [2] e7 54 [2] a0 45 [2] ee 49 [2] e2 43 [2] f5 48 [2] ee 06 [2] d3 }

  condition:
    any of them
}