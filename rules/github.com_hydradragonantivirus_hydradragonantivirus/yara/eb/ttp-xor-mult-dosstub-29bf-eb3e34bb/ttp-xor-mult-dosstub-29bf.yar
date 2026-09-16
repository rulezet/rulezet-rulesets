rule TTP_XOR_MULT_DOSStub_29bf {
  strings:
    $key_29bf = { 7d d7 [2] 09 cf [2] 4e cd [2] 09 dc [2] 47 d0 [2] 4b da [2] 5c d1 [2] 47 9f [2] 7a }

  condition:
    any of them
}