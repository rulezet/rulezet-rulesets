rule TTP_XOR_MULT_DOSStub_7bf1 {
  strings:
    $key_7bf1 = { 2f 99 [2] 5b 81 [2] 1c 83 [2] 5b 92 [2] 15 9e [2] 19 94 [2] 0e 9f [2] 15 d1 [2] 28 }

  condition:
    any of them
}