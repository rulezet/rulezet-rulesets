rule TTP_XOR_MULT_DOSStub_37d8 {
  strings:
    $key_37d8 = { 63 b0 [2] 17 a8 [2] 50 aa [2] 17 bb [2] 59 b7 [2] 55 bd [2] 42 b6 [2] 59 f8 [2] 64 }

  condition:
    any of them
}