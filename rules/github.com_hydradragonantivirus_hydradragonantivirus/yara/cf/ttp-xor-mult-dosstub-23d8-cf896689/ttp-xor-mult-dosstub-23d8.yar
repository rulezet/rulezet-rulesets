rule TTP_XOR_MULT_DOSStub_23d8 {
  strings:
    $key_23d8 = { 77 b0 [2] 03 a8 [2] 44 aa [2] 03 bb [2] 4d b7 [2] 41 bd [2] 56 b6 [2] 4d f8 [2] 70 }

  condition:
    any of them
}