rule TTP_XOR_MULT_DOSStub_1376 {
  strings:
    $key_1376 = { 47 1e [2] 33 06 [2] 74 04 [2] 33 15 [2] 7d 19 [2] 71 13 [2] 66 18 [2] 7d 56 [2] 40 }

  condition:
    any of them
}