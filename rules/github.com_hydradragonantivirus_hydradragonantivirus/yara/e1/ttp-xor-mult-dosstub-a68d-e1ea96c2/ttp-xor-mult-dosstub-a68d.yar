rule TTP_XOR_MULT_DOSStub_a68d {
  strings:
    $key_a68d = { f2 e5 [2] 86 fd [2] c1 ff [2] 86 ee [2] c8 e2 [2] c4 e8 [2] d3 e3 [2] c8 ad [2] f5 }

  condition:
    any of them
}