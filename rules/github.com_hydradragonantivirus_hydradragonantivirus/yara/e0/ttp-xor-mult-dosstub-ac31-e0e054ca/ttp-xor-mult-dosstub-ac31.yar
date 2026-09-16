rule TTP_XOR_MULT_DOSStub_ac31 {
  strings:
    $key_ac31 = { f8 59 [2] 8c 41 [2] cb 43 [2] 8c 52 [2] c2 5e [2] ce 54 [2] d9 5f [2] c2 11 [2] ff }

  condition:
    any of them
}