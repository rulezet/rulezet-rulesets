rule TTP_XOR_MULT_DOSStub_a5bf {
  strings:
    $key_a5bf = { f1 d7 [2] 85 cf [2] c2 cd [2] 85 dc [2] cb d0 [2] c7 da [2] d0 d1 [2] cb 9f [2] f6 }

  condition:
    any of them
}