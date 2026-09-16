rule TTP_XOR_MULT_DOSStub_3544 {
  strings:
    $key_3544 = { 61 2c [2] 15 34 [2] 52 36 [2] 15 27 [2] 5b 2b [2] 57 21 [2] 40 2a [2] 5b 64 [2] 66 }

  condition:
    any of them
}