rule TTP_XOR_MULT_DOSStub_8091 {
  strings:
    $key_8091 = { d4 f9 [2] a0 e1 [2] e7 e3 [2] a0 f2 [2] ee fe [2] e2 f4 [2] f5 ff [2] ee b1 [2] d3 }

  condition:
    any of them
}