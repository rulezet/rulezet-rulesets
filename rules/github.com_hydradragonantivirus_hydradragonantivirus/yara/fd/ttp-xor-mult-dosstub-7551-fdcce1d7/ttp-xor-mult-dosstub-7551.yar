rule TTP_XOR_MULT_DOSStub_7551 {
  strings:
    $key_7551 = { 21 39 [2] 55 21 [2] 12 23 [2] 55 32 [2] 1b 3e [2] 17 34 [2] 00 3f [2] 1b 71 [2] 26 }

  condition:
    any of them
}