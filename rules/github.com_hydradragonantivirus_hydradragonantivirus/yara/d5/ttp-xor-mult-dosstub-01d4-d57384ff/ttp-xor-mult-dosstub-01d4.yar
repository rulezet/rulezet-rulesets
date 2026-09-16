rule TTP_XOR_MULT_DOSStub_01d4 {
  strings:
    $key_01d4 = { 55 bc [2] 21 a4 [2] 66 a6 [2] 21 b7 [2] 6f bb [2] 63 b1 [2] 74 ba [2] 6f f4 [2] 52 }

  condition:
    any of them
}