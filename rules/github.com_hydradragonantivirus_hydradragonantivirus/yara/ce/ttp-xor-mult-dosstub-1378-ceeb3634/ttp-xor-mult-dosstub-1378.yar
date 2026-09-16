rule TTP_XOR_MULT_DOSStub_1378 {
  strings:
    $key_1378 = { 47 10 [2] 33 08 [2] 74 0a [2] 33 1b [2] 7d 17 [2] 71 1d [2] 66 16 [2] 7d 58 [2] 40 }

  condition:
    any of them
}