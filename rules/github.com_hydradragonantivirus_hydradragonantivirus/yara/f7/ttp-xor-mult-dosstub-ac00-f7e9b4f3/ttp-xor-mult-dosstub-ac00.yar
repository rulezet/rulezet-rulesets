rule TTP_XOR_MULT_DOSStub_ac00 {
  strings:
    $key_ac00 = { f8 68 [2] 8c 70 [2] cb 72 [2] 8c 63 [2] c2 6f [2] ce 65 [2] d9 6e [2] c2 20 [2] ff }

  condition:
    any of them
}