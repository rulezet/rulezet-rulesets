rule TTP_XOR_MULT_DOSStub_27d5 {
  strings:
    $key_27d5 = { 73 bd [2] 07 a5 [2] 40 a7 [2] 07 b6 [2] 49 ba [2] 45 b0 [2] 52 bb [2] 49 f5 [2] 74 }

  condition:
    any of them
}