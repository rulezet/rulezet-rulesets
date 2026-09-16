rule TTP_XOR_MULT_DOSStub_31d4 {
  strings:
    $key_31d4 = { 65 bc [2] 11 a4 [2] 56 a6 [2] 11 b7 [2] 5f bb [2] 53 b1 [2] 44 ba [2] 5f f4 [2] 62 }

  condition:
    any of them
}