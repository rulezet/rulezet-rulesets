rule TTP_XOR_MULT_DOSStub_9eb5 {
  strings:
    $key_9eb5 = { ca dd [2] be c5 [2] f9 c7 [2] be d6 [2] f0 da [2] fc d0 [2] eb db [2] f0 95 [2] cd }

  condition:
    any of them
}