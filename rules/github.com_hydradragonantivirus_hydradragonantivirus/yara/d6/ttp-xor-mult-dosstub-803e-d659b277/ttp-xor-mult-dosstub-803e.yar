rule TTP_XOR_MULT_DOSStub_803e {
  strings:
    $key_803e = { d4 56 [2] a0 4e [2] e7 4c [2] a0 5d [2] ee 51 [2] e2 5b [2] f5 50 [2] ee 1e [2] d3 }

  condition:
    any of them
}