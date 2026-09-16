rule TTP_XOR_MULT_DOSStub_0291 {
  strings:
    $key_0291 = { 56 f9 [2] 22 e1 [2] 65 e3 [2] 22 f2 [2] 6c fe [2] 60 f4 [2] 77 ff [2] 6c b1 [2] 51 }

  condition:
    any of them
}