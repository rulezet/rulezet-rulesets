rule TTP_XOR_MULT_DOSStub_9ecf {
  strings:
    $key_9ecf = { ca a7 [2] be bf [2] f9 bd [2] be ac [2] f0 a0 [2] fc aa [2] eb a1 [2] f0 ef [2] cd }

  condition:
    any of them
}