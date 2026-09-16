rule TTP_XOR_MULT_DOSStub_a2bf {
  strings:
    $key_a2bf = { f6 d7 [2] 82 cf [2] c5 cd [2] 82 dc [2] cc d0 [2] c0 da [2] d7 d1 [2] cc 9f [2] f1 }

  condition:
    any of them
}