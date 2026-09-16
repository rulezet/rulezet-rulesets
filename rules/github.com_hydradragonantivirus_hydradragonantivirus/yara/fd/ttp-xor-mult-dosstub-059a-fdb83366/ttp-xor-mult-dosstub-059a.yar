rule TTP_XOR_MULT_DOSStub_059a {
  strings:
    $key_059a = { 51 f2 [2] 25 ea [2] 62 e8 [2] 25 f9 [2] 6b f5 [2] 67 ff [2] 70 f4 [2] 6b ba [2] 56 }

  condition:
    any of them
}