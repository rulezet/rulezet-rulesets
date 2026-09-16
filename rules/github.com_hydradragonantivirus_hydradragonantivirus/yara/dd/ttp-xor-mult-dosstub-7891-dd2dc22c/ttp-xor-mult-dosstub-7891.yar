rule TTP_XOR_MULT_DOSStub_7891 {
  strings:
    $key_7891 = { 2c f9 [2] 58 e1 [2] 1f e3 [2] 58 f2 [2] 16 fe [2] 1a f4 [2] 0d ff [2] 16 b1 [2] 2b }

  condition:
    any of them
}