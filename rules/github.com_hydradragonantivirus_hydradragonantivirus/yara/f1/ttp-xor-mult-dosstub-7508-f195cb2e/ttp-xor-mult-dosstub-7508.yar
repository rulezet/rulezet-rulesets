rule TTP_XOR_MULT_DOSStub_7508 {
  strings:
    $key_7508 = { 21 60 [2] 55 78 [2] 12 7a [2] 55 6b [2] 1b 67 [2] 17 6d [2] 00 66 [2] 1b 28 [2] 26 }

  condition:
    any of them
}