rule TTP_XOR_MULT_DOSStub_6790 {
  strings:
    $key_6790 = { 33 f8 [2] 47 e0 [2] 00 e2 [2] 47 f3 [2] 09 ff [2] 05 f5 [2] 12 fe [2] 09 b0 [2] 34 }

  condition:
    any of them
}