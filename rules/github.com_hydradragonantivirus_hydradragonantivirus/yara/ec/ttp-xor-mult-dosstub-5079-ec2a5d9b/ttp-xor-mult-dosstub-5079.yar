rule TTP_XOR_MULT_DOSStub_5079 {
  strings:
    $key_5079 = { 04 11 [2] 70 09 [2] 37 0b [2] 70 1a [2] 3e 16 [2] 32 1c [2] 25 17 [2] 3e 59 [2] 03 }

  condition:
    any of them
}