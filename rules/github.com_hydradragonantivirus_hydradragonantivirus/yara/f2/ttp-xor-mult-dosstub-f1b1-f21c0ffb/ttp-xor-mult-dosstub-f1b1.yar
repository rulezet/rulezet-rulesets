rule TTP_XOR_MULT_DOSStub_f1b1 {
  strings:
    $key_f1b1 = { a5 d9 [2] d1 c1 [2] 96 c3 [2] d1 d2 [2] 9f de [2] 93 d4 [2] 84 df [2] 9f 91 [2] a2 }

  condition:
    any of them
}