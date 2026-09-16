rule TTP_XOR_MULT_DOSStub_7563 {
  strings:
    $key_7563 = { 21 0b [2] 55 13 [2] 12 11 [2] 55 00 [2] 1b 0c [2] 17 06 [2] 00 0d [2] 1b 43 [2] 26 }

  condition:
    any of them
}