rule TTP_XOR_MULT_DOSStub_1691 {
  strings:
    $key_1691 = { 42 f9 [2] 36 e1 [2] 71 e3 [2] 36 f2 [2] 78 fe [2] 74 f4 [2] 63 ff [2] 78 b1 [2] 45 }

  condition:
    any of them
}