rule TTP_XOR_MULT_DOSStub_a0b0 {
  strings:
    $key_a0b0 = { f4 d8 [2] 80 c0 [2] c7 c2 [2] 80 d3 [2] ce df [2] c2 d5 [2] d5 de [2] ce 90 [2] f3 }

  condition:
    any of them
}