rule TTP_XOR_MULT_DOSStub_9e56 {
  strings:
    $key_9e56 = { ca 3e [2] be 26 [2] f9 24 [2] be 35 [2] f0 39 [2] fc 33 [2] eb 38 [2] f0 76 [2] cd }

  condition:
    any of them
}