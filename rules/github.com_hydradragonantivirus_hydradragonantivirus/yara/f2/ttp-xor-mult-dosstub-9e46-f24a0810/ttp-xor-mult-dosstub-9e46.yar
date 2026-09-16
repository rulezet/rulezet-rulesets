rule TTP_XOR_MULT_DOSStub_9e46 {
  strings:
    $key_9e46 = { ca 2e [2] be 36 [2] f9 34 [2] be 25 [2] f0 29 [2] fc 23 [2] eb 28 [2] f0 66 [2] cd }

  condition:
    any of them
}