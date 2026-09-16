rule TTP_XOR_MULT_DOSStub_a616 {
  strings:
    $key_a616 = { f2 7e [2] 86 66 [2] c1 64 [2] 86 75 [2] c8 79 [2] c4 73 [2] d3 78 [2] c8 36 [2] f5 }

  condition:
    any of them
}