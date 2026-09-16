rule TTP_XOR_MULT_DOSStub_e246 {
  strings:
    $key_e246 = { b6 2e [2] c2 36 [2] 85 34 [2] c2 25 [2] 8c 29 [2] 80 23 [2] 97 28 [2] 8c 66 [2] b1 }

  condition:
    any of them
}