rule TTP_XOR_MULT_DOSStub_ac70 {
  strings:
    $key_ac70 = { f8 18 [2] 8c 00 [2] cb 02 [2] 8c 13 [2] c2 1f [2] ce 15 [2] d9 1e [2] c2 50 [2] ff }

  condition:
    any of them
}