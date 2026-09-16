rule TTP_XOR_MULT_DOSStub_1371 {
  strings:
    $key_1371 = { 47 19 [2] 33 01 [2] 74 03 [2] 33 12 [2] 7d 1e [2] 71 14 [2] 66 1f [2] 7d 51 [2] 40 }

  condition:
    any of them
}