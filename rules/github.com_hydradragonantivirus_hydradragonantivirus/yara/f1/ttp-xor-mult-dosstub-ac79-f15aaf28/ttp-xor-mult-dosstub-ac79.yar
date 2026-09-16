rule TTP_XOR_MULT_DOSStub_ac79 {
  strings:
    $key_ac79 = { f8 11 [2] 8c 09 [2] cb 0b [2] 8c 1a [2] c2 16 [2] ce 1c [2] d9 17 [2] c2 59 [2] ff }

  condition:
    any of them
}