rule TTP_XOR_MULT_DOSStub_9e34 {
  strings:
    $key_9e34 = { ca 5c [2] be 44 [2] f9 46 [2] be 57 [2] f0 5b [2] fc 51 [2] eb 5a [2] f0 14 [2] cd }

  condition:
    any of them
}