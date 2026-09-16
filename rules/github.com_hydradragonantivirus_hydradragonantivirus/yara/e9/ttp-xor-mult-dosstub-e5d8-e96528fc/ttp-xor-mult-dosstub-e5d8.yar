rule TTP_XOR_MULT_DOSStub_e5d8 {
  strings:
    $key_e5d8 = { b1 b0 [2] c5 a8 [2] 82 aa [2] c5 bb [2] 8b b7 [2] 87 bd [2] 90 b6 [2] 8b f8 [2] b6 }

  condition:
    any of them
}