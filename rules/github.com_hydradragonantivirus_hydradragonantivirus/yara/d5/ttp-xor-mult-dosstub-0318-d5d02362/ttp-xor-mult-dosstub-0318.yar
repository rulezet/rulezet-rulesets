rule TTP_XOR_MULT_DOSStub_0318 {
  strings:
    $key_0318 = { 57 70 [2] 23 68 [2] 64 6a [2] 23 7b [2] 6d 77 [2] 61 7d [2] 76 76 [2] 6d 38 [2] 50 }

  condition:
    any of them
}