rule TTP_XOR_MULT_DOSStub_a7aa {
  strings:
    $key_a7aa = { f3 c2 [2] 87 da [2] c0 d8 [2] 87 c9 [2] c9 c5 [2] c5 cf [2] d2 c4 [2] c9 8a [2] f4 }

  condition:
    any of them
}