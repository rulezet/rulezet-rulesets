rule TTP_XOR_MULT_DOSStub_9e5a {
  strings:
    $key_9e5a = { ca 32 [2] be 2a [2] f9 28 [2] be 39 [2] f0 35 [2] fc 3f [2] eb 34 [2] f0 7a [2] cd }

  condition:
    any of them
}