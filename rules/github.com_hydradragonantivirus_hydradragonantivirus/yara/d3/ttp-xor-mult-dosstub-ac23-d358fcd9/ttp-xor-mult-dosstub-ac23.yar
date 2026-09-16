rule TTP_XOR_MULT_DOSStub_ac23 {
  strings:
    $key_ac23 = { f8 4b [2] 8c 53 [2] cb 51 [2] 8c 40 [2] c2 4c [2] ce 46 [2] d9 4d [2] c2 03 [2] ff }

  condition:
    any of them
}