rule TTP_XOR_MULT_DOSStub_4334 {
  strings:
    $key_4334 = { 17 5c [2] 63 44 [2] 24 46 [2] 63 57 [2] 2d 5b [2] 21 51 [2] 36 5a [2] 2d 14 [2] 10 }

  condition:
    any of them
}