rule TTP_XOR_MULT_DOSStub_009a {
  strings:
    $key_009a = { 54 f2 [2] 20 ea [2] 67 e8 [2] 20 f9 [2] 6e f5 [2] 62 ff [2] 75 f4 [2] 6e ba [2] 53 }

  condition:
    any of them
}