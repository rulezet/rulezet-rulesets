rule TTP_XOR_MULT_DOSStub_65d5 {
  strings:
    $key_65d5 = { 31 bd [2] 45 a5 [2] 02 a7 [2] 45 b6 [2] 0b ba [2] 07 b0 [2] 10 bb [2] 0b f5 [2] 36 }

  condition:
    any of them
}