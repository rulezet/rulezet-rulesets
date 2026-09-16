rule TTP_XOR_MULT_DOSStub_8061 {
  strings:
    $key_8061 = { d4 09 [2] a0 11 [2] e7 13 [2] a0 02 [2] ee 0e [2] e2 04 [2] f5 0f [2] ee 41 [2] d3 }

  condition:
    any of them
}