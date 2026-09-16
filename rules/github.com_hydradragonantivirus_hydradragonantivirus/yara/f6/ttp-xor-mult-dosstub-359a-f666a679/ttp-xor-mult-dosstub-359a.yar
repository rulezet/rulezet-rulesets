rule TTP_XOR_MULT_DOSStub_359a {
  strings:
    $key_359a = { 61 f2 [2] 15 ea [2] 52 e8 [2] 15 f9 [2] 5b f5 [2] 57 ff [2] 40 f4 [2] 5b ba [2] 66 }

  condition:
    any of them
}