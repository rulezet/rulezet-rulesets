rule TTP_XOR_MULT_DOSStub_ac0f {
  strings:
    $key_ac0f = { f8 67 [2] 8c 7f [2] cb 7d [2] 8c 6c [2] c2 60 [2] ce 6a [2] d9 61 [2] c2 2f [2] ff }

  condition:
    any of them
}