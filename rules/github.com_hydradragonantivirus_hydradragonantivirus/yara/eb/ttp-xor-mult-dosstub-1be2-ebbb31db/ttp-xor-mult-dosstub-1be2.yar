rule TTP_XOR_MULT_DOSStub_1be2 {
  strings:
    $key_1be2 = { 4f 8a [2] 3b 92 [2] 7c 90 [2] 3b 81 [2] 75 8d [2] 79 87 [2] 6e 8c [2] 75 c2 [2] 48 }

  condition:
    any of them
}