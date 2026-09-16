rule TTP_XOR_MULT_DOSStub_f1d8 {
  strings:
    $key_f1d8 = { a5 b0 [2] d1 a8 [2] 96 aa [2] d1 bb [2] 9f b7 [2] 93 bd [2] 84 b6 [2] 9f f8 [2] a2 }

  condition:
    any of them
}