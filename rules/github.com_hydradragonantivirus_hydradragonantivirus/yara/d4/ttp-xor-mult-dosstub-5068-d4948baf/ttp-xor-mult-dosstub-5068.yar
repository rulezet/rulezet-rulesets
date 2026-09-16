rule TTP_XOR_MULT_DOSStub_5068 {
  strings:
    $key_5068 = { 04 00 [2] 70 18 [2] 37 1a [2] 70 0b [2] 3e 07 [2] 32 0d [2] 25 06 [2] 3e 48 [2] 03 }

  condition:
    any of them
}