rule TTP_XOR_MULT_DOSStub_f7d8 {
  strings:
    $key_f7d8 = { a3 b0 [2] d7 a8 [2] 90 aa [2] d7 bb [2] 99 b7 [2] 95 bd [2] 82 b6 [2] 99 f8 [2] a4 }

  condition:
    any of them
}