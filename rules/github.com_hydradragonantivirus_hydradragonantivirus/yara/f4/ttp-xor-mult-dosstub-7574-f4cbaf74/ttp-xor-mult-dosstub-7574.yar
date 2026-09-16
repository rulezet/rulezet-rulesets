rule TTP_XOR_MULT_DOSStub_7574 {
  strings:
    $key_7574 = { 21 1c [2] 55 04 [2] 12 06 [2] 55 17 [2] 1b 1b [2] 17 11 [2] 00 1a [2] 1b 54 [2] 26 }

  condition:
    any of them
}