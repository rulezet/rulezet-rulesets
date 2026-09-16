rule TTP_XOR_MULT_DOSStub_1f56 {
  strings:
    $key_1f56 = { 4b 3e [2] 3f 26 [2] 78 24 [2] 3f 35 [2] 71 39 [2] 7d 33 [2] 6a 38 [2] 71 76 [2] 4c }

  condition:
    any of them
}