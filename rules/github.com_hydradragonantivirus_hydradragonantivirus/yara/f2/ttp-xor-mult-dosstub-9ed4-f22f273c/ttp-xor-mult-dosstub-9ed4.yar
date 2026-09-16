rule TTP_XOR_MULT_DOSStub_9ed4 {
  strings:
    $key_9ed4 = { ca bc [2] be a4 [2] f9 a6 [2] be b7 [2] f0 bb [2] fc b1 [2] eb ba [2] f0 f4 [2] cd }

  condition:
    any of them
}