rule TTP_XOR_MULT_DOSStub_77d4 {
  strings:
    $key_77d4 = { 23 bc [2] 57 a4 [2] 10 a6 [2] 57 b7 [2] 19 bb [2] 15 b1 [2] 02 ba [2] 19 f4 [2] 24 }

  condition:
    any of them
}