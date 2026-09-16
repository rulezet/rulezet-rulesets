rule TTP_XOR_MULT_DOSStub_9ef4 {
  strings:
    $key_9ef4 = { ca 9c [2] be 84 [2] f9 86 [2] be 97 [2] f0 9b [2] fc 91 [2] eb 9a [2] f0 d4 [2] cd }

  condition:
    any of them
}