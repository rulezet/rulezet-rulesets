rule TTP_XOR_MULT_DOSStub_2d89 {
  strings:
    $key_2d89 = { 79 e1 [2] 0d f9 [2] 4a fb [2] 0d ea [2] 43 e6 [2] 4f ec [2] 58 e7 [2] 43 a9 [2] 7e }

  condition:
    any of them
}