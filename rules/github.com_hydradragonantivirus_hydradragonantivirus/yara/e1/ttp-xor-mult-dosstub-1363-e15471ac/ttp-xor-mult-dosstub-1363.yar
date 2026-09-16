rule TTP_XOR_MULT_DOSStub_1363 {
  strings:
    $key_1363 = { 47 0b [2] 33 13 [2] 74 11 [2] 33 00 [2] 7d 0c [2] 71 06 [2] 66 0d [2] 7d 43 [2] 40 }

  condition:
    any of them
}