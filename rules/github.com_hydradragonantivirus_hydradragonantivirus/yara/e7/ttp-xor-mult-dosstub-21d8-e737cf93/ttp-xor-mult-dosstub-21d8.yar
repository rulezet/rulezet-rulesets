rule TTP_XOR_MULT_DOSStub_21d8 {
  strings:
    $key_21d8 = { 75 b0 [2] 01 a8 [2] 46 aa [2] 01 bb [2] 4f b7 [2] 43 bd [2] 54 b6 [2] 4f f8 [2] 72 }

  condition:
    any of them
}