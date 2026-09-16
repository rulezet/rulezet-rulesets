rule TTP_XOR_MULT_DOSStub_46d8 {
  strings:
    $key_46d8 = { 12 b0 [2] 66 a8 [2] 21 aa [2] 66 bb [2] 28 b7 [2] 24 bd [2] 33 b6 [2] 28 f8 [2] 15 }

  condition:
    any of them
}