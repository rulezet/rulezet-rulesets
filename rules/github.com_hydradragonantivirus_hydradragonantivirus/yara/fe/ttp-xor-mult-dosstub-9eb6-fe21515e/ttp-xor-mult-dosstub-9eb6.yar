rule TTP_XOR_MULT_DOSStub_9eb6 {
  strings:
    $key_9eb6 = { ca de [2] be c6 [2] f9 c4 [2] be d5 [2] f0 d9 [2] fc d3 [2] eb d8 [2] f0 96 [2] cd }

  condition:
    any of them
}