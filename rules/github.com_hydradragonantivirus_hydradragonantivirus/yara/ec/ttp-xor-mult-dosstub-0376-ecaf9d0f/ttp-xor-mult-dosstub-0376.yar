rule TTP_XOR_MULT_DOSStub_0376 {
  strings:
    $key_0376 = { 57 1e [2] 23 06 [2] 64 04 [2] 23 15 [2] 6d 19 [2] 61 13 [2] 76 18 [2] 6d 56 [2] 50 }

  condition:
    any of them
}