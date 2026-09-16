rule TTP_XOR_MULT_DOSStub_1e9a {
  strings:
    $key_1e9a = { 4a f2 [2] 3e ea [2] 79 e8 [2] 3e f9 [2] 70 f5 [2] 7c ff [2] 6b f4 [2] 70 ba [2] 4d }

  condition:
    any of them
}