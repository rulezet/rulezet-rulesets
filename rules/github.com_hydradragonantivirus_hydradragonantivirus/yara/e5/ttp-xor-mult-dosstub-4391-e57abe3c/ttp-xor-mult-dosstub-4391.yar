rule TTP_XOR_MULT_DOSStub_4391 {
  strings:
    $key_4391 = { 17 f9 [2] 63 e1 [2] 24 e3 [2] 63 f2 [2] 2d fe [2] 21 f4 [2] 36 ff [2] 2d b1 [2] 10 }

  condition:
    any of them
}