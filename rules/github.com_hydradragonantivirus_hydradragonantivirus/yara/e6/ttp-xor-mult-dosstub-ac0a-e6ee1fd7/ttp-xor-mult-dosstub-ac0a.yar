rule TTP_XOR_MULT_DOSStub_ac0a {
  strings:
    $key_ac0a = { f8 62 [2] 8c 7a [2] cb 78 [2] 8c 69 [2] c2 65 [2] ce 6f [2] d9 64 [2] c2 2a [2] ff }

  condition:
    any of them
}