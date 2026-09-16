rule TTP_XOR_MULT_DOSStub_9ed9 {
  strings:
    $key_9ed9 = { ca b1 [2] be a9 [2] f9 ab [2] be ba [2] f0 b6 [2] fc bc [2] eb b7 [2] f0 f9 [2] cd }

  condition:
    any of them
}