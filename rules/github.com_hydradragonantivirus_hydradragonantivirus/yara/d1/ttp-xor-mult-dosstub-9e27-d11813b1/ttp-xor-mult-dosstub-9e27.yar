rule TTP_XOR_MULT_DOSStub_9e27 {
  strings:
    $key_9e27 = { ca 4f [2] be 57 [2] f9 55 [2] be 44 [2] f0 48 [2] fc 42 [2] eb 49 [2] f0 07 [2] cd }

  condition:
    any of them
}