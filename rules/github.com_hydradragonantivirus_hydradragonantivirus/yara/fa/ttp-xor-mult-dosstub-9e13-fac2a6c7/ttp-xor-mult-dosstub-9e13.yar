rule TTP_XOR_MULT_DOSStub_9e13 {
  strings:
    $key_9e13 = { ca 7b [2] be 63 [2] f9 61 [2] be 70 [2] f0 7c [2] fc 76 [2] eb 7d [2] f0 33 [2] cd }

  condition:
    any of them
}