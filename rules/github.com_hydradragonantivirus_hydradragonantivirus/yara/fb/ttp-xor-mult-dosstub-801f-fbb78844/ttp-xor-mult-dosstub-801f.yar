rule TTP_XOR_MULT_DOSStub_801f {
  strings:
    $key_801f = { d4 77 [2] a0 6f [2] e7 6d [2] a0 7c [2] ee 70 [2] e2 7a [2] f5 71 [2] ee 3f [2] d3 }

  condition:
    any of them
}