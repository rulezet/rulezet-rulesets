rule TTP_XOR_MULT_DOSStub_f2d8 {
  strings:
    $key_f2d8 = { a6 b0 [2] d2 a8 [2] 95 aa [2] d2 bb [2] 9c b7 [2] 90 bd [2] 87 b6 [2] 9c f8 [2] a1 }

  condition:
    any of them
}