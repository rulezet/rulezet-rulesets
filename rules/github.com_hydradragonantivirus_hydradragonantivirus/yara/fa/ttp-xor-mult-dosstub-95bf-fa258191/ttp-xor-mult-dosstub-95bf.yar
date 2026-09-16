rule TTP_XOR_MULT_DOSStub_95bf {
  strings:
    $key_95bf = { c1 d7 [2] b5 cf [2] f2 cd [2] b5 dc [2] fb d0 [2] f7 da [2] e0 d1 [2] fb 9f [2] c6 }

  condition:
    any of them
}