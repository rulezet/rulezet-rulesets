rule TTP_XOR_MULT_DOSStub_1991 {
  strings:
    $key_1991 = { 4d f9 [2] 39 e1 [2] 7e e3 [2] 39 f2 [2] 77 fe [2] 7b f4 [2] 6c ff [2] 77 b1 [2] 4a }

  condition:
    any of them
}