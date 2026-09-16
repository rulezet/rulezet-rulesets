rule TTP_XOR_MULT_DOSStub_4379 {
  strings:
    $key_4379 = { 17 11 [2] 63 09 [2] 24 0b [2] 63 1a [2] 2d 16 [2] 21 1c [2] 36 17 [2] 2d 59 [2] 10 }

  condition:
    any of them
}