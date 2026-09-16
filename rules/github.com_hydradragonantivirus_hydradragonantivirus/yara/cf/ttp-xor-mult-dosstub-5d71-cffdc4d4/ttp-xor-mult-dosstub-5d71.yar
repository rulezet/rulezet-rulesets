rule TTP_XOR_MULT_DOSStub_5d71 {
  strings:
    $key_5d71 = { 09 19 [2] 7d 01 [2] 3a 03 [2] 7d 12 [2] 33 1e [2] 3f 14 [2] 28 1f [2] 33 51 [2] 0e }

  condition:
    any of them
}