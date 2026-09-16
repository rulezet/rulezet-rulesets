rule TTP_XOR_MULT_DOSStub_a688 {
  strings:
    $key_a688 = { f2 e0 [2] 86 f8 [2] c1 fa [2] 86 eb [2] c8 e7 [2] c4 ed [2] d3 e6 [2] c8 a8 [2] f5 }

  condition:
    any of them
}