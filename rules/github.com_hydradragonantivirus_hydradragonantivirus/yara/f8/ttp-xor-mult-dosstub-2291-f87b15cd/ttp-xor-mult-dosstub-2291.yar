rule TTP_XOR_MULT_DOSStub_2291 {
  strings:
    $key_2291 = { 76 f9 [2] 02 e1 [2] 45 e3 [2] 02 f2 [2] 4c fe [2] 40 f4 [2] 57 ff [2] 4c b1 [2] 71 }

  condition:
    any of them
}