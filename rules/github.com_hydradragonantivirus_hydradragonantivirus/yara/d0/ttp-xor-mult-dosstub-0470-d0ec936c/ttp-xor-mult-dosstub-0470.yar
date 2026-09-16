rule TTP_XOR_MULT_DOSStub_0470 {
  strings:
    $key_0470 = { 50 18 [2] 24 00 [2] 63 02 [2] 24 13 [2] 6a 1f [2] 66 15 [2] 71 1e [2] 6a 50 [2] 57 }

  condition:
    any of them
}