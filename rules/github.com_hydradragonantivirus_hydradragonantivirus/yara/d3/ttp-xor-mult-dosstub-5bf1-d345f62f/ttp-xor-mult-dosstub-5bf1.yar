rule TTP_XOR_MULT_DOSStub_5bf1 {
  strings:
    $key_5bf1 = { 0f 99 [2] 7b 81 [2] 3c 83 [2] 7b 92 [2] 35 9e [2] 39 94 [2] 2e 9f [2] 35 d1 [2] 08 }

  condition:
    any of them
}