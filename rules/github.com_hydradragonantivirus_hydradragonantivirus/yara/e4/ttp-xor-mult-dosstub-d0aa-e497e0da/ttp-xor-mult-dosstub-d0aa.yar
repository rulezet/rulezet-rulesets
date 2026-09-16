rule TTP_XOR_MULT_DOSStub_d0aa {
  strings:
    $key_d0aa = { 84 c2 [2] f0 da [2] b7 d8 [2] f0 c9 [2] be c5 [2] b2 cf [2] a5 c4 [2] be 8a [2] 83 }

  condition:
    any of them
}