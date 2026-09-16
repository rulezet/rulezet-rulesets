rule TTP_XOR_MULT_DOSStub_73d8 {
  strings:
    $key_73d8 = { 27 b0 [2] 53 a8 [2] 14 aa [2] 53 bb [2] 1d b7 [2] 11 bd [2] 06 b6 [2] 1d f8 [2] 20 }

  condition:
    any of them
}