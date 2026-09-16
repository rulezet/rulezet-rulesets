rule TTP_XOR_MULT_DOSStub_f140 {
  strings:
    $key_f140 = { a5 28 [2] d1 30 [2] 96 32 [2] d1 23 [2] 9f 2f [2] 93 25 [2] 84 2e [2] 9f 60 [2] a2 }

  condition:
    any of them
}