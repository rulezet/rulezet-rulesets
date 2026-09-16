rule TTP_XOR_MULT_DOSStub_5176 {
  strings:
    $key_5176 = { 05 1e [2] 71 06 [2] 36 04 [2] 71 15 [2] 3f 19 [2] 33 13 [2] 24 18 [2] 3f 56 [2] 02 }

  condition:
    any of them
}