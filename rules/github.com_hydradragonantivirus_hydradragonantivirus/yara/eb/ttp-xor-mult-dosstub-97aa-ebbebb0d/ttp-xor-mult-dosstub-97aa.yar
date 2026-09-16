rule TTP_XOR_MULT_DOSStub_97aa {
  strings:
    $key_97aa = { c3 c2 [2] b7 da [2] f0 d8 [2] b7 c9 [2] f9 c5 [2] f5 cf [2] e2 c4 [2] f9 8a [2] c4 }

  condition:
    any of them
}