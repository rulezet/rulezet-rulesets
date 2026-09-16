rule TTP_XOR_MULT_DOSStub_309a {
  strings:
    $key_309a = { 64 f2 [2] 10 ea [2] 57 e8 [2] 10 f9 [2] 5e f5 [2] 52 ff [2] 45 f4 [2] 5e ba [2] 63 }

  condition:
    any of them
}