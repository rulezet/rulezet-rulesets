rule TTP_XOR_MULT_DOSStub_d9d8 {
  strings:
    $key_d9d8 = { 8d b0 [2] f9 a8 [2] be aa [2] f9 bb [2] b7 b7 [2] bb bd [2] ac b6 [2] b7 f8 [2] 8a }

  condition:
    any of them
}