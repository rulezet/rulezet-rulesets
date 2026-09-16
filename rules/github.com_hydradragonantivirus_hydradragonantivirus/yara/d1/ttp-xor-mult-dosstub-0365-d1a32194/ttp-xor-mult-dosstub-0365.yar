rule TTP_XOR_MULT_DOSStub_0365 {
  strings:
    $key_0365 = { 57 0d [2] 23 15 [2] 64 17 [2] 23 06 [2] 6d 0a [2] 61 00 [2] 76 0b [2] 6d 45 [2] 50 }

  condition:
    any of them
}