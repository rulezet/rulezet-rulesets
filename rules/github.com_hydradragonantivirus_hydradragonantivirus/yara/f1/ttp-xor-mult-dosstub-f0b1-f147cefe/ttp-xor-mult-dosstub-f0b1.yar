rule TTP_XOR_MULT_DOSStub_f0b1 {
  strings:
    $key_f0b1 = { a4 d9 [2] d0 c1 [2] 97 c3 [2] d0 d2 [2] 9e de [2] 92 d4 [2] 85 df [2] 9e 91 [2] a3 }

  condition:
    any of them
}