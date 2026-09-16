rule TTP_XOR_MULT_DOSStub_ac74 {
  strings:
    $key_ac74 = { f8 1c [2] 8c 04 [2] cb 06 [2] 8c 17 [2] c2 1b [2] ce 11 [2] d9 1a [2] c2 54 [2] ff }

  condition:
    any of them
}