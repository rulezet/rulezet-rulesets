rule TTP_XOR_MULT_DOSStub_4e91 {
  strings:
    $key_4e91 = { 1a f9 [2] 6e e1 [2] 29 e3 [2] 6e f2 [2] 20 fe [2] 2c f4 [2] 3b ff [2] 20 b1 [2] 1d }

  condition:
    any of them
}