rule TTP_XOR_MULT_DOSStub_4318 {
  strings:
    $key_4318 = { 17 70 [2] 63 68 [2] 24 6a [2] 63 7b [2] 2d 77 [2] 21 7d [2] 36 76 [2] 2d 38 [2] 10 }

  condition:
    any of them
}