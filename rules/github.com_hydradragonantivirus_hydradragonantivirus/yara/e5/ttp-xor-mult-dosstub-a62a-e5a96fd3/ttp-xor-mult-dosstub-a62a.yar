rule TTP_XOR_MULT_DOSStub_a62a {
  strings:
    $key_a62a = { f2 42 [2] 86 5a [2] c1 58 [2] 86 49 [2] c8 45 [2] c4 4f [2] d3 44 [2] c8 0a [2] f5 }

  condition:
    any of them
}