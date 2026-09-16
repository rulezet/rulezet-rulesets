rule TTP_XOR_MULT_DOSStub_14d8 {
  strings:
    $key_14d8 = { 40 b0 [2] 34 a8 [2] 73 aa [2] 34 bb [2] 7a b7 [2] 76 bd [2] 61 b6 [2] 7a f8 [2] 47 }

  condition:
    any of them
}