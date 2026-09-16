rule TTP_XOR_MULT_DOSStub_3bf1 {
  strings:
    $key_3bf1 = { 6f 99 [2] 1b 81 [2] 5c 83 [2] 1b 92 [2] 55 9e [2] 59 94 [2] 4e 9f [2] 55 d1 [2] 68 }

  condition:
    any of them
}