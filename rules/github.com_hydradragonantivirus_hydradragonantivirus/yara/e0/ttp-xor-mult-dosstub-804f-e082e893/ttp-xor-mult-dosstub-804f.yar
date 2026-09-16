rule TTP_XOR_MULT_DOSStub_804f {
  strings:
    $key_804f = { d4 27 [2] a0 3f [2] e7 3d [2] a0 2c [2] ee 20 [2] e2 2a [2] f5 21 [2] ee 6f [2] d3 }

  condition:
    any of them
}