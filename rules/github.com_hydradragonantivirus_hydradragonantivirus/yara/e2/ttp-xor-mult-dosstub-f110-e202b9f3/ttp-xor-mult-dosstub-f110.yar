rule TTP_XOR_MULT_DOSStub_f110 {
  strings:
    $key_f110 = { a5 78 [2] d1 60 [2] 96 62 [2] d1 73 [2] 9f 7f [2] 93 75 [2] 84 7e [2] 9f 30 [2] a2 }

  condition:
    any of them
}