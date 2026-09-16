rule TTP_XOR_MULT_DOSStub_1990 {
  strings:
    $key_1990 = { 4d f8 [2] 39 e0 [2] 7e e2 [2] 39 f3 [2] 77 ff [2] 7b f5 [2] 6c fe [2] 77 b0 [2] 4a }

  condition:
    any of them
}