rule TTP_XOR_MULT_DOSStub_2165 {
  strings:
    $key_2165 = { 75 0d [2] 01 15 [2] 46 17 [2] 01 06 [2] 4f 0a [2] 43 00 [2] 54 0b [2] 4f 45 [2] 72 }

  condition:
    any of them
}