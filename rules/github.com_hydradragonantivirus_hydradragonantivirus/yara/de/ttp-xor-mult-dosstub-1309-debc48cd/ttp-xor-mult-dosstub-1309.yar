rule TTP_XOR_MULT_DOSStub_1309 {
  strings:
    $key_1309 = { 47 61 [2] 33 79 [2] 74 7b [2] 33 6a [2] 7d 66 [2] 71 6c [2] 66 67 [2] 7d 29 [2] 40 }

  condition:
    any of them
}