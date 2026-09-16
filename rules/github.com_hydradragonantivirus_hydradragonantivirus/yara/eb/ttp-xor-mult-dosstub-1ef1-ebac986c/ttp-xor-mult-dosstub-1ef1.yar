rule TTP_XOR_MULT_DOSStub_1ef1 {
  strings:
    $key_1ef1 = { 4a 99 [2] 3e 81 [2] 79 83 [2] 3e 92 [2] 70 9e [2] 7c 94 [2] 6b 9f [2] 70 d1 [2] 4d }

  condition:
    any of them
}