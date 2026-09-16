rule TTP_XOR_MULT_DOSStub_7690 {
  strings:
    $key_7690 = { 22 f8 [2] 56 e0 [2] 11 e2 [2] 56 f3 [2] 18 ff [2] 14 f5 [2] 03 fe [2] 18 b0 [2] 25 }

  condition:
    any of them
}