rule TTP_XOR_MULT_DOSStub_2d86 {
  strings:
    $key_2d86 = { 79 ee [2] 0d f6 [2] 4a f4 [2] 0d e5 [2] 43 e9 [2] 4f e3 [2] 58 e8 [2] 43 a6 [2] 7e }

  condition:
    any of them
}