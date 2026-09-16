rule TTP_XOR_MULT_DOSStub_801d {
  strings:
    $key_801d = { d4 75 [2] a0 6d [2] e7 6f [2] a0 7e [2] ee 72 [2] e2 78 [2] f5 73 [2] ee 3d [2] d3 }

  condition:
    any of them
}