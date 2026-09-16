rule TTP_XOR_MULT_DOSStub_47d8 {
  strings:
    $key_47d8 = { 13 b0 [2] 67 a8 [2] 20 aa [2] 67 bb [2] 29 b7 [2] 25 bd [2] 32 b6 [2] 29 f8 [2] 14 }

  condition:
    any of them
}