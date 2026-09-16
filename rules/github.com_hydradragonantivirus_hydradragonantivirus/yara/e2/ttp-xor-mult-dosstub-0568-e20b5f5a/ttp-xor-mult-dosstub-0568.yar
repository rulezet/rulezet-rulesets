rule TTP_XOR_MULT_DOSStub_0568 {
  strings:
    $key_0568 = { 51 00 [2] 25 18 [2] 62 1a [2] 25 0b [2] 6b 07 [2] 67 0d [2] 70 06 [2] 6b 48 [2] 56 }

  condition:
    any of them
}