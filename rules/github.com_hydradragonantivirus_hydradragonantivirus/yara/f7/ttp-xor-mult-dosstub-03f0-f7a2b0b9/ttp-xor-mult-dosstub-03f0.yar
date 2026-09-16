rule TTP_XOR_MULT_DOSStub_03f0 {
  strings:
    $key_03f0 = { 57 98 [2] 23 80 [2] 64 82 [2] 23 93 [2] 6d 9f [2] 61 95 [2] 76 9e [2] 6d d0 [2] 50 }

  condition:
    any of them
}