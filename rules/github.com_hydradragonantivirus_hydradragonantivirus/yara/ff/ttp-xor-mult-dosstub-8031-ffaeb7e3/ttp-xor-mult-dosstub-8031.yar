rule TTP_XOR_MULT_DOSStub_8031 {
  strings:
    $key_8031 = { d4 59 [2] a0 41 [2] e7 43 [2] a0 52 [2] ee 5e [2] e2 54 [2] f5 5f [2] ee 11 [2] d3 }

  condition:
    any of them
}