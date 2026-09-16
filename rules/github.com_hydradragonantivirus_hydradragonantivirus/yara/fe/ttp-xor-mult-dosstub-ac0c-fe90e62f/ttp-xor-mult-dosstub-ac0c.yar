rule TTP_XOR_MULT_DOSStub_ac0c {
  strings:
    $key_ac0c = { f8 64 [2] 8c 7c [2] cb 7e [2] 8c 6f [2] c2 63 [2] ce 69 [2] d9 62 [2] c2 2c [2] ff }

  condition:
    any of them
}