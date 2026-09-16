rule TTP_XOR_MULT_DOSStub_21d4 {
  strings:
    $key_21d4 = { 75 bc [2] 01 a4 [2] 46 a6 [2] 01 b7 [2] 4f bb [2] 43 b1 [2] 54 ba [2] 4f f4 [2] 72 }

  condition:
    any of them
}