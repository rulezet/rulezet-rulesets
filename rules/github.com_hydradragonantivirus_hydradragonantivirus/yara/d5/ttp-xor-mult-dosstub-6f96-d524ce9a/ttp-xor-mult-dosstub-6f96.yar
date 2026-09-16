rule TTP_XOR_MULT_DOSStub_6f96 {
  strings:
    $key_6f96 = { 3b fe [2] 4f e6 [2] 08 e4 [2] 4f f5 [2] 01 f9 [2] 0d f3 [2] 1a f8 [2] 01 b6 [2] 3c }

  condition:
    any of them
}