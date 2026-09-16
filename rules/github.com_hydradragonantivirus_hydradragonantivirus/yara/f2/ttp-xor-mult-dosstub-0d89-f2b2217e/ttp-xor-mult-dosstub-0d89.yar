rule TTP_XOR_MULT_DOSStub_0d89 {
  strings:
    $key_0d89 = { 59 e1 [2] 2d f9 [2] 6a fb [2] 2d ea [2] 63 e6 [2] 6f ec [2] 78 e7 [2] 63 a9 [2] 5e }

  condition:
    any of them
}