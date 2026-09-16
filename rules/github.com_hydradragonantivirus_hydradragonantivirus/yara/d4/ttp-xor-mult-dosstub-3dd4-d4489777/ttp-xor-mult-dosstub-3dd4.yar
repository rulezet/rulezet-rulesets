rule TTP_XOR_MULT_DOSStub_3dd4 {
  strings:
    $key_3dd4 = { 69 bc [2] 1d a4 [2] 5a a6 [2] 1d b7 [2] 53 bb [2] 5f b1 [2] 48 ba [2] 53 f4 [2] 6e }

  condition:
    any of them
}