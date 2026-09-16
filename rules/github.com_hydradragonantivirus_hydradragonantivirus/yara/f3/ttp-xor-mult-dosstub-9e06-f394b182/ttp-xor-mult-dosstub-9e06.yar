rule TTP_XOR_MULT_DOSStub_9e06 {
  strings:
    $key_9e06 = { ca 6e [2] be 76 [2] f9 74 [2] be 65 [2] f0 69 [2] fc 63 [2] eb 68 [2] f0 26 [2] cd }

  condition:
    any of them
}