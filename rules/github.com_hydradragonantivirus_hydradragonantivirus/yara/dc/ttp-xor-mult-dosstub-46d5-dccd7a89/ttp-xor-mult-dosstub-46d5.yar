rule TTP_XOR_MULT_DOSStub_46d5 {
  strings:
    $key_46d5 = { 12 bd [2] 66 a5 [2] 21 a7 [2] 66 b6 [2] 28 ba [2] 24 b0 [2] 33 bb [2] 28 f5 [2] 15 }

  condition:
    any of them
}