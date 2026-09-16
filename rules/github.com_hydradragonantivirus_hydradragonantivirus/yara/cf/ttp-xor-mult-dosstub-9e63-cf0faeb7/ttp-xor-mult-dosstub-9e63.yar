rule TTP_XOR_MULT_DOSStub_9e63 {
  strings:
    $key_9e63 = { ca 0b [2] be 13 [2] f9 11 [2] be 00 [2] f0 0c [2] fc 06 [2] eb 0d [2] f0 43 [2] cd }

  condition:
    any of them
}