rule TTP_XOR_MULT_DOSStub_22f0 {
  strings:
    $key_22f0 = { 76 98 [2] 02 80 [2] 45 82 [2] 02 93 [2] 4c 9f [2] 40 95 [2] 57 9e [2] 4c d0 [2] 71 }

  condition:
    any of them
}