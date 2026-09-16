rule TTP_XOR_MULT_DOSStub_4590 {
  strings:
    $key_4590 = { 11 f8 [2] 65 e0 [2] 22 e2 [2] 65 f3 [2] 2b ff [2] 27 f5 [2] 30 fe [2] 2b b0 [2] 16 }

  condition:
    any of them
}