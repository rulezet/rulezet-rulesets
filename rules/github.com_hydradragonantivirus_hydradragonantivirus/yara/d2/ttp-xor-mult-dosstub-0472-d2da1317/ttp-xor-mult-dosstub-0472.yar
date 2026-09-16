rule TTP_XOR_MULT_DOSStub_0472 {
  strings:
    $key_0472 = { 50 1a [2] 24 02 [2] 63 00 [2] 24 11 [2] 6a 1d [2] 66 17 [2] 71 1c [2] 6a 52 [2] 57 }

  condition:
    any of them
}