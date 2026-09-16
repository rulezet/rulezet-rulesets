rule TTP_XOR_MULT_DOSStub_1379 {
  strings:
    $key_1379 = { 47 11 [2] 33 09 [2] 74 0b [2] 33 1a [2] 7d 16 [2] 71 1c [2] 66 17 [2] 7d 59 [2] 40 }

  condition:
    any of them
}