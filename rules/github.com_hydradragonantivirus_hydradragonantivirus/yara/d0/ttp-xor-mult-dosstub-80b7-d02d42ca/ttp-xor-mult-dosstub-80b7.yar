rule TTP_XOR_MULT_DOSStub_80b7 {
  strings:
    $key_80b7 = { d4 df [2] a0 c7 [2] e7 c5 [2] a0 d4 [2] ee d8 [2] e2 d2 [2] f5 d9 [2] ee 97 [2] d3 }

  condition:
    any of them
}