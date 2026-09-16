rule TTP_XOR_MULT_DOSStub_80d7 {
  strings:
    $key_80d7 = { d4 bf [2] a0 a7 [2] e7 a5 [2] a0 b4 [2] ee b8 [2] e2 b2 [2] f5 b9 [2] ee f7 [2] d3 }

  condition:
    any of them
}