rule TTP_XOR_MULT_DOSStub_e251 {
  strings:
    $key_e251 = { b6 39 [2] c2 21 [2] 85 23 [2] c2 32 [2] 8c 3e [2] 80 34 [2] 97 3f [2] 8c 71 [2] b1 }

  condition:
    any of them
}