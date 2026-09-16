rule TTP_XOR_MULT_DOSStub_802d {
  strings:
    $key_802d = { d4 45 [2] a0 5d [2] e7 5f [2] a0 4e [2] ee 42 [2] e2 48 [2] f5 43 [2] ee 0d [2] d3 }

  condition:
    any of them
}