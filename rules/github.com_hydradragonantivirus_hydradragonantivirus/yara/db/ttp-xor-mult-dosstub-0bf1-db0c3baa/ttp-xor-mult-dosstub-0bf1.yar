rule TTP_XOR_MULT_DOSStub_0bf1 {
  strings:
    $key_0bf1 = { 5f 99 [2] 2b 81 [2] 6c 83 [2] 2b 92 [2] 65 9e [2] 69 94 [2] 7e 9f [2] 65 d1 [2] 58 }

  condition:
    any of them
}