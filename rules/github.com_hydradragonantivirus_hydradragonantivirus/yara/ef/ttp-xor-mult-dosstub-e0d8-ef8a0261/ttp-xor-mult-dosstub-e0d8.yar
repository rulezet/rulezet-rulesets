rule TTP_XOR_MULT_DOSStub_e0d8 {
  strings:
    $key_e0d8 = { b4 b0 [2] c0 a8 [2] 87 aa [2] c0 bb [2] 8e b7 [2] 82 bd [2] 95 b6 [2] 8e f8 [2] b3 }

  condition:
    any of them
}