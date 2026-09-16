rule TTP_XOR_MULT_DOSStub_1b76 {
  strings:
    $key_1b76 = { 4f 1e [2] 3b 06 [2] 7c 04 [2] 3b 15 [2] 75 19 [2] 79 13 [2] 6e 18 [2] 75 56 [2] 48 }

  condition:
    any of them
}