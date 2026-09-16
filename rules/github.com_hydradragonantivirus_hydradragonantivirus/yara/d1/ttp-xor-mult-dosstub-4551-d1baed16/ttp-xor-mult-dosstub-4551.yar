rule TTP_XOR_MULT_DOSStub_4551 {
  strings:
    $key_4551 = { 11 39 [2] 65 21 [2] 22 23 [2] 65 32 [2] 2b 3e [2] 27 34 [2] 30 3f [2] 2b 71 [2] 16 }

  condition:
    any of them
}