rule TTP_XOR_MULT_DOSStub_0316 {
  strings:
    $key_0316 = { 57 7e [2] 23 66 [2] 64 64 [2] 23 75 [2] 6d 79 [2] 61 73 [2] 76 78 [2] 6d 36 [2] 50 }

  condition:
    any of them
}