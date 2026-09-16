rule TTP_XOR_MULT_DOSStub_2265 {
  strings:
    $key_2265 = { 76 0d [2] 02 15 [2] 45 17 [2] 02 06 [2] 4c 0a [2] 40 00 [2] 57 0b [2] 4c 45 [2] 71 }

  condition:
    any of them
}