rule TTP_XOR_MULT_DOSStub_0302 {
  strings:
    $key_0302 = { 57 6a [2] 23 72 [2] 64 70 [2] 23 61 [2] 6d 6d [2] 61 67 [2] 76 6c [2] 6d 22 [2] 50 }

  condition:
    any of them
}