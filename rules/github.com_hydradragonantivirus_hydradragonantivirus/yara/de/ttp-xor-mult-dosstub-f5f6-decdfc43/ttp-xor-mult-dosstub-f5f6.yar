rule TTP_XOR_MULT_DOSStub_f5f6 {
  strings:
    $key_f5f6 = { a1 9e [2] d5 86 [2] 92 84 [2] d5 95 [2] 9b 99 [2] 97 93 [2] 80 98 [2] 9b d6 [2] a6 }

  condition:
    any of them
}