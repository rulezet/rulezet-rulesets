rule TTP_XOR_MULT_DOSStub_7e9a {
  strings:
    $key_7e9a = { 2a f2 [2] 5e ea [2] 19 e8 [2] 5e f9 [2] 10 f5 [2] 1c ff [2] 0b f4 [2] 10 ba [2] 2d }

  condition:
    any of them
}