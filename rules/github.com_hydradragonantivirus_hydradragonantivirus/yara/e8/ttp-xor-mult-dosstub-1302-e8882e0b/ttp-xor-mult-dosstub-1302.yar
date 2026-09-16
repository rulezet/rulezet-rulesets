rule TTP_XOR_MULT_DOSStub_1302 {
  strings:
    $key_1302 = { 47 6a [2] 33 72 [2] 74 70 [2] 33 61 [2] 7d 6d [2] 71 67 [2] 66 6c [2] 7d 22 [2] 40 }

  condition:
    any of them
}