rule TTP_XOR_MULT_DOSStub_7679 {
  strings:
    $key_7679 = { 22 11 [2] 56 09 [2] 11 0b [2] 56 1a [2] 18 16 [2] 14 1c [2] 03 17 [2] 18 59 [2] 25 }

  condition:
    any of them
}