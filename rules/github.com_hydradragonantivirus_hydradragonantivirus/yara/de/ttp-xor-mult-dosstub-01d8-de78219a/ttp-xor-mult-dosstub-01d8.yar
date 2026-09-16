rule TTP_XOR_MULT_DOSStub_01d8 {
  strings:
    $key_01d8 = { 55 b0 [2] 21 a8 [2] 66 aa [2] 21 bb [2] 6f b7 [2] 63 bd [2] 74 b6 [2] 6f f8 [2] 52 }

  condition:
    any of them
}