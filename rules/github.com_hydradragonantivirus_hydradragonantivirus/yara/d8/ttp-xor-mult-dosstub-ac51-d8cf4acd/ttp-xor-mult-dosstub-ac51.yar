rule TTP_XOR_MULT_DOSStub_ac51 {
  strings:
    $key_ac51 = { f8 39 [2] 8c 21 [2] cb 23 [2] 8c 32 [2] c2 3e [2] ce 34 [2] d9 3f [2] c2 71 [2] ff }

  condition:
    any of them
}