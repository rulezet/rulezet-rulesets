rule TTP_XOR_MULT_DOSStub_139a {
  strings:
    $key_139a = { 47 f2 [2] 33 ea [2] 74 e8 [2] 33 f9 [2] 7d f5 [2] 71 ff [2] 66 f4 [2] 7d ba [2] 40 }

  condition:
    any of them
}