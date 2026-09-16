rule TTP_XOR_MULT_DOSStub_1308 {
  strings:
    $key_1308 = { 47 60 [2] 33 78 [2] 74 7a [2] 33 6b [2] 7d 67 [2] 71 6d [2] 66 66 [2] 7d 28 [2] 40 }

  condition:
    any of them
}