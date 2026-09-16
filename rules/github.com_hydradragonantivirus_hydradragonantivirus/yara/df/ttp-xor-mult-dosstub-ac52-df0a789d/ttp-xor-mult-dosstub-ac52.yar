rule TTP_XOR_MULT_DOSStub_ac52 {
  strings:
    $key_ac52 = { f8 3a [2] 8c 22 [2] cb 20 [2] 8c 31 [2] c2 3d [2] ce 37 [2] d9 3c [2] c2 72 [2] ff }

  condition:
    any of them
}