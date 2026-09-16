rule TTP_XOR_MULT_DOSStub_0ff1 {
  strings:
    $key_0ff1 = { 5b 99 [2] 2f 81 [2] 68 83 [2] 2f 92 [2] 61 9e [2] 6d 94 [2] 7a 9f [2] 61 d1 [2] 5c }

  condition:
    any of them
}