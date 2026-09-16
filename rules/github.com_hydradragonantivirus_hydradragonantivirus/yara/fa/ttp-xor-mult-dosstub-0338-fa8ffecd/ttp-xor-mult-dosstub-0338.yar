rule TTP_XOR_MULT_DOSStub_0338 {
  strings:
    $key_0338 = { 57 50 [2] 23 48 [2] 64 4a [2] 23 5b [2] 6d 57 [2] 61 5d [2] 76 56 [2] 6d 18 [2] 50 }

  condition:
    any of them
}