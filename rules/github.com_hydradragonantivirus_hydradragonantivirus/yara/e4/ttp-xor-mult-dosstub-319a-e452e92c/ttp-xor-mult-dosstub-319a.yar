rule TTP_XOR_MULT_DOSStub_319a {
  strings:
    $key_319a = { 65 f2 [2] 11 ea [2] 56 e8 [2] 11 f9 [2] 5f f5 [2] 53 ff [2] 44 f4 [2] 5f ba [2] 62 }

  condition:
    any of them
}