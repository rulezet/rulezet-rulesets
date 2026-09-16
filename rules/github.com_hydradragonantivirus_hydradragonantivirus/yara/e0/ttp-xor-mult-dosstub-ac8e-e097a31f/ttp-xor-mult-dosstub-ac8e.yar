rule TTP_XOR_MULT_DOSStub_ac8e {
  strings:
    $key_ac8e = { f8 e6 [2] 8c fe [2] cb fc [2] 8c ed [2] c2 e1 [2] ce eb [2] d9 e0 [2] c2 ae [2] ff }

  condition:
    any of them
}