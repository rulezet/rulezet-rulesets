rule TTP_XOR_MULT_DOSStub_acca {
  strings:
    $key_acca = { f8 a2 [2] 8c ba [2] cb b8 [2] 8c a9 [2] c2 a5 [2] ce af [2] d9 a4 [2] c2 ea [2] ff }

  condition:
    any of them
}