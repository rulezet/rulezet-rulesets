rule TTP_XOR_MULT_DOSStub_7cd5 {
  strings:
    $key_7cd5 = { 28 bd [2] 5c a5 [2] 1b a7 [2] 5c b6 [2] 12 ba [2] 1e b0 [2] 09 bb [2] 12 f5 [2] 2f }

  condition:
    any of them
}