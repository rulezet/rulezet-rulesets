rule TTP_XOR_MULT_DOSStub_0791 {
  strings:
    $key_0791 = { 53 f9 [2] 27 e1 [2] 60 e3 [2] 27 f2 [2] 69 fe [2] 65 f4 [2] 72 ff [2] 69 b1 [2] 54 }

  condition:
    any of them
}