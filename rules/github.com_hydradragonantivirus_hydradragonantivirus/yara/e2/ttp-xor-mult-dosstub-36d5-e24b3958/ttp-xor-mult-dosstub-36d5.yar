rule TTP_XOR_MULT_DOSStub_36d5 {
  strings:
    $key_36d5 = { 62 bd [2] 16 a5 [2] 51 a7 [2] 16 b6 [2] 58 ba [2] 54 b0 [2] 43 bb [2] 58 f5 [2] 65 }

  condition:
    any of them
}