rule TTP_XOR_MULT_DOSStub_f7f6 {
  strings:
    $key_f7f6 = { a3 9e [2] d7 86 [2] 90 84 [2] d7 95 [2] 99 99 [2] 95 93 [2] 82 98 [2] 99 d6 [2] a4 }

  condition:
    any of them
}