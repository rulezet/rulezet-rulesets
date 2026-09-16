rule TTP_XOR_MULT_DOSStub_9e98 {
  strings:
    $key_9e98 = { ca f0 [2] be e8 [2] f9 ea [2] be fb [2] f0 f7 [2] fc fd [2] eb f6 [2] f0 b8 [2] cd }

  condition:
    any of them
}