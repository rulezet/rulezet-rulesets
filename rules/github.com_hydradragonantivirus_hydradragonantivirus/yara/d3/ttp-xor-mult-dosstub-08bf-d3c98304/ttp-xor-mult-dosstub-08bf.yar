rule TTP_XOR_MULT_DOSStub_08bf {
  strings:
    $key_08bf = { 5c d7 [2] 28 cf [2] 6f cd [2] 28 dc [2] 66 d0 [2] 6a da [2] 7d d1 [2] 66 9f [2] 5b }

  condition:
    any of them
}