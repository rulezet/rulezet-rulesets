rule TTP_XOR_MULT_DOSStub_8021 {
  strings:
    $key_8021 = { d4 49 [2] a0 51 [2] e7 53 [2] a0 42 [2] ee 4e [2] e2 44 [2] f5 4f [2] ee 01 [2] d3 }

  condition:
    any of them
}