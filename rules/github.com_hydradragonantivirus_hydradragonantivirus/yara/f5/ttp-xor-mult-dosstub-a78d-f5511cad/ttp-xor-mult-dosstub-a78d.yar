rule TTP_XOR_MULT_DOSStub_a78d {
  strings:
    $key_a78d = { f3 e5 [2] 87 fd [2] c0 ff [2] 87 ee [2] c9 e2 [2] c5 e8 [2] d2 e3 [2] c9 ad [2] f4 }

  condition:
    any of them
}