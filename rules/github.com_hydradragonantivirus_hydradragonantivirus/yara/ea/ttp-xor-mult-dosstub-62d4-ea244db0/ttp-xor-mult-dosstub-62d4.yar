rule TTP_XOR_MULT_DOSStub_62d4 {
  strings:
    $key_62d4 = { 36 bc [2] 42 a4 [2] 05 a6 [2] 42 b7 [2] 0c bb [2] 00 b1 [2] 17 ba [2] 0c f4 [2] 31 }

  condition:
    any of them
}