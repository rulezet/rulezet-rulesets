rule TTP_XOR_MULT_DOSStub_75d8 {
  strings:
    $key_75d8 = { 21 b0 [2] 55 a8 [2] 12 aa [2] 55 bb [2] 1b b7 [2] 17 bd [2] 00 b6 [2] 1b f8 [2] 26 }

  condition:
    any of them
}