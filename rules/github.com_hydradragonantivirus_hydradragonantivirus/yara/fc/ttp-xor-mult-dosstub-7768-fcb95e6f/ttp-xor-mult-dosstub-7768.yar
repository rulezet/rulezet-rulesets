rule TTP_XOR_MULT_DOSStub_7768 {
  strings:
    $key_7768 = { 23 00 [2] 57 18 [2] 10 1a [2] 57 0b [2] 19 07 [2] 15 0d [2] 02 06 [2] 19 48 [2] 24 }

  condition:
    any of them
}