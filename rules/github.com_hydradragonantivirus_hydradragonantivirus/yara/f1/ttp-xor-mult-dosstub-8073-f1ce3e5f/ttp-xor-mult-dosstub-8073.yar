rule TTP_XOR_MULT_DOSStub_8073 {
  strings:
    $key_8073 = { d4 1b [2] a0 03 [2] e7 01 [2] a0 10 [2] ee 1c [2] e2 16 [2] f5 1d [2] ee 53 [2] d3 }

  condition:
    any of them
}