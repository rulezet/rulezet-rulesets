rule TTP_XOR_MULT_DOSStub_0334 {
  strings:
    $key_0334 = { 57 5c [2] 23 44 [2] 64 46 [2] 23 57 [2] 6d 5b [2] 61 51 [2] 76 5a [2] 6d 14 [2] 50 }

  condition:
    any of them
}