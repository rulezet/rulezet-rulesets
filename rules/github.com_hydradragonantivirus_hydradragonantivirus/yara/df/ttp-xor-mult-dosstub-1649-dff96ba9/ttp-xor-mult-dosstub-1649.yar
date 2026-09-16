rule TTP_XOR_MULT_DOSStub_1649 {
  strings:
    $key_1649 = { 42 21 [2] 36 39 [2] 71 3b [2] 36 2a [2] 78 26 [2] 74 2c [2] 63 27 [2] 78 69 [2] 45 }

  condition:
    any of them
}