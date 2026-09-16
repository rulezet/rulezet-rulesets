rule TTP_XOR_MULT_DOSStub_63d8 {
  strings:
    $key_63d8 = { 37 b0 [2] 43 a8 [2] 04 aa [2] 43 bb [2] 0d b7 [2] 01 bd [2] 16 b6 [2] 0d f8 [2] 30 }

  condition:
    any of them
}