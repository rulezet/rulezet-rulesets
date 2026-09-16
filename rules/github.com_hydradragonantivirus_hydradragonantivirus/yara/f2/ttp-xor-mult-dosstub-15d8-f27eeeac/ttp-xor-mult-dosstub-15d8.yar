rule TTP_XOR_MULT_DOSStub_15d8 {
  strings:
    $key_15d8 = { 41 b0 [2] 35 a8 [2] 72 aa [2] 35 bb [2] 7b b7 [2] 77 bd [2] 60 b6 [2] 7b f8 [2] 46 }

  condition:
    any of them
}