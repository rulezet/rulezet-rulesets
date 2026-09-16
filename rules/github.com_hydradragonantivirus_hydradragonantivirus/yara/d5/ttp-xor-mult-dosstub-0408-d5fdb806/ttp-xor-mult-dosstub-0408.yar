rule TTP_XOR_MULT_DOSStub_0408 {
  strings:
    $key_0408 = { 50 60 [2] 24 78 [2] 63 7a [2] 24 6b [2] 6a 67 [2] 66 6d [2] 71 66 [2] 6a 28 [2] 57 }

  condition:
    any of them
}