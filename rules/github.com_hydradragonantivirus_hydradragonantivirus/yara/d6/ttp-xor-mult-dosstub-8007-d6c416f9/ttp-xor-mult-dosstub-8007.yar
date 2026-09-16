rule TTP_XOR_MULT_DOSStub_8007 {
  strings:
    $key_8007 = { d4 6f [2] a0 77 [2] e7 75 [2] a0 64 [2] ee 68 [2] e2 62 [2] f5 69 [2] ee 27 [2] d3 }

  condition:
    any of them
}