rule TTP_XOR_MULT_DOSStub_7790 {
  strings:
    $key_7790 = { 23 f8 [2] 57 e0 [2] 10 e2 [2] 57 f3 [2] 19 ff [2] 15 f5 [2] 02 fe [2] 19 b0 [2] 24 }

  condition:
    any of them
}