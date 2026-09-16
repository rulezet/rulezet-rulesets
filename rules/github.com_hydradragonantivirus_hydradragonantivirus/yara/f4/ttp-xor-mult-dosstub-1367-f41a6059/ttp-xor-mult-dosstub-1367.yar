rule TTP_XOR_MULT_DOSStub_1367 {
  strings:
    $key_1367 = { 47 0f [2] 33 17 [2] 74 15 [2] 33 04 [2] 7d 08 [2] 71 02 [2] 66 09 [2] 7d 47 [2] 40 }

  condition:
    any of them
}