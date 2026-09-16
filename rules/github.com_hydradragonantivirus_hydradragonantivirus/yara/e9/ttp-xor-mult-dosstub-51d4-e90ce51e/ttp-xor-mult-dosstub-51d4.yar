rule TTP_XOR_MULT_DOSStub_51d4 {
  strings:
    $key_51d4 = { 05 bc [2] 71 a4 [2] 36 a6 [2] 71 b7 [2] 3f bb [2] 33 b1 [2] 24 ba [2] 3f f4 [2] 02 }

  condition:
    any of them
}