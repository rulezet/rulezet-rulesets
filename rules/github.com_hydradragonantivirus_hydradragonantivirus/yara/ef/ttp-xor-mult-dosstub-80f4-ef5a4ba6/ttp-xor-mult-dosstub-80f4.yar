rule TTP_XOR_MULT_DOSStub_80f4 {
  strings:
    $key_80f4 = { d4 9c [2] a0 84 [2] e7 86 [2] a0 97 [2] ee 9b [2] e2 91 [2] f5 9a [2] ee d4 [2] d3 }

  condition:
    any of them
}