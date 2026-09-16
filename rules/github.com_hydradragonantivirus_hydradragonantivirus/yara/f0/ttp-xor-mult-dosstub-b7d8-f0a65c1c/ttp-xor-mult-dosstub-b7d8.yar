rule TTP_XOR_MULT_DOSStub_b7d8 {
  strings:
    $key_b7d8 = { e3 b0 [2] 97 a8 [2] d0 aa [2] 97 bb [2] d9 b7 [2] d5 bd [2] c2 b6 [2] d9 f8 [2] e4 }

  condition:
    any of them
}