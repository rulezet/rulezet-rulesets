rule TTP_XOR_MULT_DOSStub_ac0b {
  strings:
    $key_ac0b = { f8 63 [2] 8c 7b [2] cb 79 [2] 8c 68 [2] c2 64 [2] ce 6e [2] d9 65 [2] c2 2b [2] ff }

  condition:
    any of them
}