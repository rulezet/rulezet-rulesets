rule TTP_XOR_MULT_DOSStub_0172 {
  strings:
    $key_0172 = { 55 1a [2] 21 02 [2] 66 00 [2] 21 11 [2] 6f 1d [2] 63 17 [2] 74 1c [2] 6f 52 [2] 52 }

  condition:
    any of them
}