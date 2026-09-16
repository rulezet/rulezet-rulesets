rule TTP_XOR_MULT_DOSStub_7fcb {
  strings:
    $key_7fcb = { 2b a3 [2] 5f bb [2] 18 b9 [2] 5f a8 [2] 11 a4 [2] 1d ae [2] 0a a5 [2] 11 eb [2] 2c }

  condition:
    any of them
}