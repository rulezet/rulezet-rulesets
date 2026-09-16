rule TTP_XOR_MULT_DOSStub_ac45 {
  strings:
    $key_ac45 = { f8 2d [2] 8c 35 [2] cb 37 [2] 8c 26 [2] c2 2a [2] ce 20 [2] d9 2b [2] c2 65 [2] ff }

  condition:
    any of them
}