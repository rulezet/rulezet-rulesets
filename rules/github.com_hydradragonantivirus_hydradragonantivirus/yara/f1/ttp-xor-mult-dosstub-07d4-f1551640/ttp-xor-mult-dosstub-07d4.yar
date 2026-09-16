rule TTP_XOR_MULT_DOSStub_07d4 {
  strings:
    $key_07d4 = { 53 bc [2] 27 a4 [2] 60 a6 [2] 27 b7 [2] 69 bb [2] 65 b1 [2] 72 ba [2] 69 f4 [2] 54 }

  condition:
    any of them
}