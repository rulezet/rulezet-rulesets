rule TTP_XOR_MULT_DOSStub_4a38 {
  strings:
    $key_4a38 = { 1e 50 [2] 6a 48 [2] 2d 4a [2] 6a 5b [2] 24 57 [2] 28 5d [2] 3f 56 [2] 24 18 [2] 19 }

  condition:
    any of them
}