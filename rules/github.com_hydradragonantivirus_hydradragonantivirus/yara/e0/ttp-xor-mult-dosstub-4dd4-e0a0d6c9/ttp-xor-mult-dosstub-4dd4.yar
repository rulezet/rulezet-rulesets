rule TTP_XOR_MULT_DOSStub_4dd4 {
  strings:
    $key_4dd4 = { 19 bc [2] 6d a4 [2] 2a a6 [2] 6d b7 [2] 23 bb [2] 2f b1 [2] 38 ba [2] 23 f4 [2] 1e }

  condition:
    any of them
}