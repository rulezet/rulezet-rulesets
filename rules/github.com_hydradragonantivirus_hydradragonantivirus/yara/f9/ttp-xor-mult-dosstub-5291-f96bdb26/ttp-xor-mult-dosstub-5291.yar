rule TTP_XOR_MULT_DOSStub_5291 {
  strings:
    $key_5291 = { 06 f9 [2] 72 e1 [2] 35 e3 [2] 72 f2 [2] 3c fe [2] 30 f4 [2] 27 ff [2] 3c b1 [2] 01 }

  condition:
    any of them
}