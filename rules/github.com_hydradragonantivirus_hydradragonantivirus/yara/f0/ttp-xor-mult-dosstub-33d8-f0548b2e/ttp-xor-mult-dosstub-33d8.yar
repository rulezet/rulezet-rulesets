rule TTP_XOR_MULT_DOSStub_33d8 {
  strings:
    $key_33d8 = { 67 b0 [2] 13 a8 [2] 54 aa [2] 13 bb [2] 5d b7 [2] 51 bd [2] 46 b6 [2] 5d f8 [2] 60 }

  condition:
    any of them
}