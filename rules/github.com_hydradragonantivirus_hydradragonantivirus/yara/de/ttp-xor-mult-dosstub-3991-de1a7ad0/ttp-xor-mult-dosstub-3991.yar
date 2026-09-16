rule TTP_XOR_MULT_DOSStub_3991 {
  strings:
    $key_3991 = { 6d f9 [2] 19 e1 [2] 5e e3 [2] 19 f2 [2] 57 fe [2] 5b f4 [2] 4c ff [2] 57 b1 [2] 6a }

  condition:
    any of them
}