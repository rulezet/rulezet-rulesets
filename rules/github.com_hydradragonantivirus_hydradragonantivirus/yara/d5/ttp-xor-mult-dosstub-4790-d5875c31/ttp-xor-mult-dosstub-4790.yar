rule TTP_XOR_MULT_DOSStub_4790 {
  strings:
    $key_4790 = { 13 f8 [2] 67 e0 [2] 20 e2 [2] 67 f3 [2] 29 ff [2] 25 f5 [2] 32 fe [2] 29 b0 [2] 14 }

  condition:
    any of them
}