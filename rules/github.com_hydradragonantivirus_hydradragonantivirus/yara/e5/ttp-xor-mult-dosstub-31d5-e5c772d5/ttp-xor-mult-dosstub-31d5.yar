rule TTP_XOR_MULT_DOSStub_31d5 {
  strings:
    $key_31d5 = { 65 bd [2] 11 a5 [2] 56 a7 [2] 11 b6 [2] 5f ba [2] 53 b0 [2] 44 bb [2] 5f f5 [2] 62 }

  condition:
    any of them
}