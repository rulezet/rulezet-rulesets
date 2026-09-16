rule TTP_XOR_MULT_DOSStub_11d4 {
  strings:
    $key_11d4 = { 45 bc [2] 31 a4 [2] 76 a6 [2] 31 b7 [2] 7f bb [2] 73 b1 [2] 64 ba [2] 7f f4 [2] 42 }

  condition:
    any of them
}