rule TTP_XOR_MULT_DOSStub_804e {
  strings:
    $key_804e = { d4 26 [2] a0 3e [2] e7 3c [2] a0 2d [2] ee 21 [2] e2 2b [2] f5 20 [2] ee 6e [2] d3 }

  condition:
    any of them
}