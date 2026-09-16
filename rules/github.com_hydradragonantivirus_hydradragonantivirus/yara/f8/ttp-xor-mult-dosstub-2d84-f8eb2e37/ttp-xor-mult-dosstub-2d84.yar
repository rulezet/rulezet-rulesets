rule TTP_XOR_MULT_DOSStub_2d84 {
  strings:
    $key_2d84 = { 79 ec [2] 0d f4 [2] 4a f6 [2] 0d e7 [2] 43 eb [2] 4f e1 [2] 58 ea [2] 43 a4 [2] 7e }

  condition:
    any of them
}