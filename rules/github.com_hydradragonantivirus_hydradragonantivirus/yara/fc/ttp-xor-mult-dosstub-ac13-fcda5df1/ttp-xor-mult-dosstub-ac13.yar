rule TTP_XOR_MULT_DOSStub_ac13 {
  strings:
    $key_ac13 = { f8 7b [2] 8c 63 [2] cb 61 [2] 8c 70 [2] c2 7c [2] ce 76 [2] d9 7d [2] c2 33 [2] ff }

  condition:
    any of them
}