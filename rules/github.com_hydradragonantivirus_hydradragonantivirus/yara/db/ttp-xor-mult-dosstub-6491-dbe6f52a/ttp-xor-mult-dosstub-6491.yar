rule TTP_XOR_MULT_DOSStub_6491 {
  strings:
    $key_6491 = { 30 f9 [2] 44 e1 [2] 03 e3 [2] 44 f2 [2] 0a fe [2] 06 f4 [2] 11 ff [2] 0a b1 [2] 37 }

  condition:
    any of them
}