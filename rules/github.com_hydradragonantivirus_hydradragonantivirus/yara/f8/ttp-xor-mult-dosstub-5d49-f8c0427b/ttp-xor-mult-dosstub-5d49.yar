rule TTP_XOR_MULT_DOSStub_5d49 {
  strings:
    $key_5d49 = { 09 21 [2] 7d 39 [2] 3a 3b [2] 7d 2a [2] 33 26 [2] 3f 2c [2] 28 27 [2] 33 69 [2] 0e }

  condition:
    any of them
}