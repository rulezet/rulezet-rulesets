rule TTP_XOR_MULT_DOSStub_8067 {
  strings:
    $key_8067 = { d4 0f [2] a0 17 [2] e7 15 [2] a0 04 [2] ee 08 [2] e2 02 [2] f5 09 [2] ee 47 [2] d3 }

  condition:
    any of them
}