rule TTP_XOR_MULT_DOSStub_67d4 {
  strings:
    $key_67d4 = { 33 bc [2] 47 a4 [2] 00 a6 [2] 47 b7 [2] 09 bb [2] 05 b1 [2] 12 ba [2] 09 f4 [2] 34 }

  condition:
    any of them
}