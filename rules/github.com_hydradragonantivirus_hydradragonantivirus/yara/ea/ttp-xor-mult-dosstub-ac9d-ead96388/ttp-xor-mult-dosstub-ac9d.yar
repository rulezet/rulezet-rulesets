rule TTP_XOR_MULT_DOSStub_ac9d {
  strings:
    $key_ac9d = { f8 f5 [2] 8c ed [2] cb ef [2] 8c fe [2] c2 f2 [2] ce f8 [2] d9 f3 [2] c2 bd [2] ff }

  condition:
    any of them
}