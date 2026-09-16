rule TTP_XOR_MULT_DOSStub_43d8 {
  strings:
    $key_43d8 = { 17 b0 [2] 63 a8 [2] 24 aa [2] 63 bb [2] 2d b7 [2] 21 bd [2] 36 b6 [2] 2d f8 [2] 10 }

  condition:
    any of them
}