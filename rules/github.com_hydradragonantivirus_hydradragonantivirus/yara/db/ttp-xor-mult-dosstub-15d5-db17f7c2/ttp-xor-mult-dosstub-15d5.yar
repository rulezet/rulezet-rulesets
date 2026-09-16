rule TTP_XOR_MULT_DOSStub_15d5 {
  strings:
    $key_15d5 = { 41 bd [2] 35 a5 [2] 72 a7 [2] 35 b6 [2] 7b ba [2] 77 b0 [2] 60 bb [2] 7b f5 [2] 46 }

  condition:
    any of them
}