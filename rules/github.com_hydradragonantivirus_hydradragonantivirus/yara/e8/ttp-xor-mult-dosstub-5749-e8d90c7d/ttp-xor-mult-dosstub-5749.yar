rule TTP_XOR_MULT_DOSStub_5749 {
  strings:
    $key_5749 = { 03 21 [2] 77 39 [2] 30 3b [2] 77 2a [2] 39 26 [2] 35 2c [2] 22 27 [2] 39 69 [2] 04 }

  condition:
    any of them
}