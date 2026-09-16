rule TTP_XOR_MULT_DOSStub_1a14 {
  strings:
    $key_1a14 = { 4e 7c [2] 3a 64 [2] 7d 66 [2] 3a 77 [2] 74 7b [2] 78 71 [2] 6f 7a [2] 74 34 [2] 49 }

  condition:
    any of them
}