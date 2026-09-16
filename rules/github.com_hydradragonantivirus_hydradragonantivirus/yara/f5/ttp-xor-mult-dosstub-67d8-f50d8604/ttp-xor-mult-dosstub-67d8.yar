rule TTP_XOR_MULT_DOSStub_67d8 {
  strings:
    $key_67d8 = { 33 b0 [2] 47 a8 [2] 00 aa [2] 47 bb [2] 09 b7 [2] 05 bd [2] 12 b6 [2] 09 f8 [2] 34 }

  condition:
    any of them
}