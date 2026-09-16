rule TTP_XOR_MULT_DOSStub_4371 {
  strings:
    $key_4371 = { 17 19 [2] 63 01 [2] 24 03 [2] 63 12 [2] 2d 1e [2] 21 14 [2] 36 1f [2] 2d 51 [2] 10 }

  condition:
    any of them
}