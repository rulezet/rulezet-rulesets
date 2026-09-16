rule TTP_XOR_MULT_DOSStub_9ed0 {
  strings:
    $key_9ed0 = { ca b8 [2] be a0 [2] f9 a2 [2] be b3 [2] f0 bf [2] fc b5 [2] eb be [2] f0 f0 [2] cd }

  condition:
    any of them
}