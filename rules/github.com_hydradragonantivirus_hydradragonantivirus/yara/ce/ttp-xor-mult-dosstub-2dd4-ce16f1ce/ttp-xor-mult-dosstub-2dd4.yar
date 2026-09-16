rule TTP_XOR_MULT_DOSStub_2dd4 {
  strings:
    $key_2dd4 = { 79 bc [2] 0d a4 [2] 4a a6 [2] 0d b7 [2] 43 bb [2] 4f b1 [2] 58 ba [2] 43 f4 [2] 7e }

  condition:
    any of them
}