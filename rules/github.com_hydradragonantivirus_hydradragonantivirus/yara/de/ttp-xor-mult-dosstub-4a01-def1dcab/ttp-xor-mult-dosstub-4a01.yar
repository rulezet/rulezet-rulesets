rule TTP_XOR_MULT_DOSStub_4a01 {
  strings:
    $key_4a01 = { 1e 69 [2] 6a 71 [2] 2d 73 [2] 6a 62 [2] 24 6e [2] 28 64 [2] 3f 6f [2] 24 21 [2] 19 }

  condition:
    any of them
}