rule TTP_XOR_MULT_DOSStub_7555 {
  strings:
    $key_7555 = { 21 3d [2] 55 25 [2] 12 27 [2] 55 36 [2] 1b 3a [2] 17 30 [2] 00 3b [2] 1b 75 [2] 26 }

  condition:
    any of them
}