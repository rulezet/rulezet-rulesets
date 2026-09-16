rule TTP_XOR_MULT_DOSStub_f485 {
  strings:
    $key_f485 = { a0 ed [2] d4 f5 [2] 93 f7 [2] d4 e6 [2] 9a ea [2] 96 e0 [2] 81 eb [2] 9a a5 [2] a7 }

  condition:
    any of them
}