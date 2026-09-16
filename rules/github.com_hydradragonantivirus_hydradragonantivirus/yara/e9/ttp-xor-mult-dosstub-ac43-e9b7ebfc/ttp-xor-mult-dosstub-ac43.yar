rule TTP_XOR_MULT_DOSStub_ac43 {
  strings:
    $key_ac43 = { f8 2b [2] 8c 33 [2] cb 31 [2] 8c 20 [2] c2 2c [2] ce 26 [2] d9 2d [2] c2 63 [2] ff }

  condition:
    any of them
}