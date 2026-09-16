rule TTP_XOR_MULT_DOSStub_ac06 {
  strings:
    $key_ac06 = { f8 6e [2] 8c 76 [2] cb 74 [2] 8c 65 [2] c2 69 [2] ce 63 [2] d9 68 [2] c2 26 [2] ff }

  condition:
    any of them
}