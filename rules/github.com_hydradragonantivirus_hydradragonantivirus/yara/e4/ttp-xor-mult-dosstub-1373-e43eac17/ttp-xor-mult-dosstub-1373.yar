rule TTP_XOR_MULT_DOSStub_1373 {
  strings:
    $key_1373 = { 47 1b [2] 33 03 [2] 74 01 [2] 33 10 [2] 7d 1c [2] 71 16 [2] 66 1d [2] 7d 53 [2] 40 }

  condition:
    any of them
}