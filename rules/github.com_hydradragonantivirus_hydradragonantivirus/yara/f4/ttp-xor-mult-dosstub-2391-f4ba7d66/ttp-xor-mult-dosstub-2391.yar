rule TTP_XOR_MULT_DOSStub_2391 {
  strings:
    $key_2391 = { 77 f9 [2] 03 e1 [2] 44 e3 [2] 03 f2 [2] 4d fe [2] 41 f4 [2] 56 ff [2] 4d b1 [2] 70 }

  condition:
    any of them
}