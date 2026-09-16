rule TTP_XOR_MULT_DOSStub_9e95 {
  strings:
    $key_9e95 = { ca fd [2] be e5 [2] f9 e7 [2] be f6 [2] f0 fa [2] fc f0 [2] eb fb [2] f0 b5 [2] cd }

  condition:
    any of them
}