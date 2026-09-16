rule TTP_XOR_MULT_DOSStub_9ef9 {
  strings:
    $key_9ef9 = { ca 91 [2] be 89 [2] f9 8b [2] be 9a [2] f0 96 [2] fc 9c [2] eb 97 [2] f0 d9 [2] cd }

  condition:
    any of them
}