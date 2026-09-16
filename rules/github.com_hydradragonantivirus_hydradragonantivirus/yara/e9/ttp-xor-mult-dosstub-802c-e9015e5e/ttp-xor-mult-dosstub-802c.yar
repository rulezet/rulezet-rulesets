rule TTP_XOR_MULT_DOSStub_802c {
  strings:
    $key_802c = { d4 44 [2] a0 5c [2] e7 5e [2] a0 4f [2] ee 43 [2] e2 49 [2] f5 42 [2] ee 0c [2] d3 }

  condition:
    any of them
}