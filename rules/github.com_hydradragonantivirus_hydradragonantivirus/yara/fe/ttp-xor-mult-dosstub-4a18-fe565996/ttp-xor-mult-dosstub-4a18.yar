rule TTP_XOR_MULT_DOSStub_4a18 {
  strings:
    $key_4a18 = { 1e 70 [2] 6a 68 [2] 2d 6a [2] 6a 7b [2] 24 77 [2] 28 7d [2] 3f 76 [2] 24 38 [2] 19 }

  condition:
    any of them
}