rule TTP_XOR_MULT_DOSStub_9cd8 {
  strings:
    $key_9cd8 = { c8 b0 [2] bc a8 [2] fb aa [2] bc bb [2] f2 b7 [2] fe bd [2] e9 b6 [2] f2 f8 [2] cf }

  condition:
    any of them
}