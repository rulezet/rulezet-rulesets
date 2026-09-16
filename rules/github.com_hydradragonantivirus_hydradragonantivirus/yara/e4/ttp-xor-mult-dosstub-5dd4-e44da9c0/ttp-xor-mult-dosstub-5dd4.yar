rule TTP_XOR_MULT_DOSStub_5dd4 {
  strings:
    $key_5dd4 = { 09 bc [2] 7d a4 [2] 3a a6 [2] 7d b7 [2] 33 bb [2] 3f b1 [2] 28 ba [2] 33 f4 [2] 0e }

  condition:
    any of them
}