rule TTP_XOR_MULT_DOSStub_1314 {
  strings:
    $key_1314 = { 47 7c [2] 33 64 [2] 74 66 [2] 33 77 [2] 7d 7b [2] 71 71 [2] 66 7a [2] 7d 34 [2] 40 }

  condition:
    any of them
}