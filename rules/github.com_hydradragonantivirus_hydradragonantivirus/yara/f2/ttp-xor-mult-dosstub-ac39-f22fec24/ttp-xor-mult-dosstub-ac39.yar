rule TTP_XOR_MULT_DOSStub_ac39 {
  strings:
    $key_ac39 = { f8 51 [2] 8c 49 [2] cb 4b [2] 8c 5a [2] c2 56 [2] ce 5c [2] d9 57 [2] c2 19 [2] ff }

  condition:
    any of them
}