rule TTP_XOR_MULT_DOSStub_1375 {
  strings:
    $key_1375 = { 47 1d [2] 33 05 [2] 74 07 [2] 33 16 [2] 7d 1a [2] 71 10 [2] 66 1b [2] 7d 55 [2] 40 }

  condition:
    any of them
}