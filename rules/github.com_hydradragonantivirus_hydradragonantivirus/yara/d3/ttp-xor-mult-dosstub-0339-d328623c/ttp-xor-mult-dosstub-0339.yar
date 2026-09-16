rule TTP_XOR_MULT_DOSStub_0339 {
  strings:
    $key_0339 = { 57 51 [2] 23 49 [2] 64 4b [2] 23 5a [2] 6d 56 [2] 61 5c [2] 76 57 [2] 6d 19 [2] 50 }

  condition:
    any of them
}