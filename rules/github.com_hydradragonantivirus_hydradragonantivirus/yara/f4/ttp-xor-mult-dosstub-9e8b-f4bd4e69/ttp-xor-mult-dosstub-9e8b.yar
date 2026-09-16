rule TTP_XOR_MULT_DOSStub_9e8b {
  strings:
    $key_9e8b = { ca e3 [2] be fb [2] f9 f9 [2] be e8 [2] f0 e4 [2] fc ee [2] eb e5 [2] f0 ab [2] cd }

  condition:
    any of them
}