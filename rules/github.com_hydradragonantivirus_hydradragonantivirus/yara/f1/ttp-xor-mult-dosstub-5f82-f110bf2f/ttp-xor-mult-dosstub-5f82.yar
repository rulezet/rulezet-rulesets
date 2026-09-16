rule TTP_XOR_MULT_DOSStub_5f82 {
  strings:
    $key_5f82 = { 0b ea [2] 7f f2 [2] 38 f0 [2] 7f e1 [2] 31 ed [2] 3d e7 [2] 2a ec [2] 31 a2 [2] 0c }

  condition:
    any of them
}