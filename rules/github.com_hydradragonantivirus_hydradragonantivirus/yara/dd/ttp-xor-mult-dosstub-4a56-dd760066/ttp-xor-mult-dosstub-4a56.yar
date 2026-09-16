rule TTP_XOR_MULT_DOSStub_4a56 {
  strings:
    $key_4a56 = { 1e 3e [2] 6a 26 [2] 2d 24 [2] 6a 35 [2] 24 39 [2] 28 33 [2] 3f 38 [2] 24 76 [2] 19 }

  condition:
    any of them
}