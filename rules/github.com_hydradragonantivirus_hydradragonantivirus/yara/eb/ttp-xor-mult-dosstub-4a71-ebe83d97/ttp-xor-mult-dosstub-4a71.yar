rule TTP_XOR_MULT_DOSStub_4a71 {
  strings:
    $key_4a71 = { 1e 19 [2] 6a 01 [2] 2d 03 [2] 6a 12 [2] 24 1e [2] 28 14 [2] 3f 1f [2] 24 51 [2] 19 }

  condition:
    any of them
}