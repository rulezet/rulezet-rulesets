rule TTP_XOR_MULT_DOSStub_6dd4 {
  strings:
    $key_6dd4 = { 39 bc [2] 4d a4 [2] 0a a6 [2] 4d b7 [2] 03 bb [2] 0f b1 [2] 18 ba [2] 03 f4 [2] 3e }

  condition:
    any of them
}