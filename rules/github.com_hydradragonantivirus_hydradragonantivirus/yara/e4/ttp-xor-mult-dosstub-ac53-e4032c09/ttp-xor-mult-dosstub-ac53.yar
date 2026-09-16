rule TTP_XOR_MULT_DOSStub_ac53 {
  strings:
    $key_ac53 = { f8 3b [2] 8c 23 [2] cb 21 [2] 8c 30 [2] c2 3c [2] ce 36 [2] d9 3d [2] c2 73 [2] ff }

  condition:
    any of them
}