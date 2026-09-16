rule TTP_XOR_MULT_DOSStub_4e97 {
  strings:
    $key_4e97 = { 1a ff [2] 6e e7 [2] 29 e5 [2] 6e f4 [2] 20 f8 [2] 2c f2 [2] 3b f9 [2] 20 b7 [2] 1d }

  condition:
    any of them
}