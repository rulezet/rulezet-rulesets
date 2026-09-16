rule TTP_XOR_MULT_DOSStub_679a {
  strings:
    $key_679a = { 33 f2 [2] 47 ea [2] 00 e8 [2] 47 f9 [2] 09 f5 [2] 05 ff [2] 12 f4 [2] 09 ba [2] 34 }

  condition:
    any of them
}