rule TTP_XOR_MULT_DOSStub_9e47 {
  strings:
    $key_9e47 = { ca 2f [2] be 37 [2] f9 35 [2] be 24 [2] f0 28 [2] fc 22 [2] eb 29 [2] f0 67 [2] cd }

  condition:
    any of them
}