rule TTP_XOR_MULT_DOSStub_0348 {
  strings:
    $key_0348 = { 57 20 [2] 23 38 [2] 64 3a [2] 23 2b [2] 6d 27 [2] 61 2d [2] 76 26 [2] 6d 68 [2] 50 }

  condition:
    any of them
}