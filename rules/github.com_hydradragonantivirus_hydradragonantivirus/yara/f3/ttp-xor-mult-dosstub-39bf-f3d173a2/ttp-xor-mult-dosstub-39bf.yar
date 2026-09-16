rule TTP_XOR_MULT_DOSStub_39bf {
  strings:
    $key_39bf = { 6d d7 [2] 19 cf [2] 5e cd [2] 19 dc [2] 57 d0 [2] 5b da [2] 4c d1 [2] 57 9f [2] 6a }

  condition:
    any of them
}