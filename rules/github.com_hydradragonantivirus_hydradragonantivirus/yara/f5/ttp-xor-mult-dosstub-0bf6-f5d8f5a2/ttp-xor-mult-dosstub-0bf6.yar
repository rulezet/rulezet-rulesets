rule TTP_XOR_MULT_DOSStub_0bf6 {
  strings:
    $key_0bf6 = { 5f 9e [2] 2b 86 [2] 6c 84 [2] 2b 95 [2] 65 99 [2] 69 93 [2] 7e 98 [2] 65 d6 [2] 58 }

  condition:
    any of them
}