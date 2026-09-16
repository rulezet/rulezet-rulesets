rule TTP_XOR_MULT_DOSStub_2896 {
  strings:
    $key_2896 = { 7c fe [2] 08 e6 [2] 4f e4 [2] 08 f5 [2] 46 f9 [2] 4a f3 [2] 5d f8 [2] 46 b6 [2] 7b }

  condition:
    any of them
}