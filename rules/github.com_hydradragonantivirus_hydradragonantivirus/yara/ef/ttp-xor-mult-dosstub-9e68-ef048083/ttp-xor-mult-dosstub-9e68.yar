rule TTP_XOR_MULT_DOSStub_9e68 {
  strings:
    $key_9e68 = { ca 00 [2] be 18 [2] f9 1a [2] be 0b [2] f0 07 [2] fc 0d [2] eb 06 [2] f0 48 [2] cd }

  condition:
    any of them
}