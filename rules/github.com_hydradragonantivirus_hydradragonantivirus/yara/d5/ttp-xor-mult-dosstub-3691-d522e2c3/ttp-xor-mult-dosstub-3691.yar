rule TTP_XOR_MULT_DOSStub_3691 {
  strings:
    $key_3691 = { 62 f9 [2] 16 e1 [2] 51 e3 [2] 16 f2 [2] 58 fe [2] 54 f4 [2] 43 ff [2] 58 b1 [2] 65 }

  condition:
    any of them
}