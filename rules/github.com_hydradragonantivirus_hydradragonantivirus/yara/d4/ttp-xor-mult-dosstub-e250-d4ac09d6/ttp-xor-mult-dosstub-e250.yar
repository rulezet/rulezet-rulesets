rule TTP_XOR_MULT_DOSStub_e250 {
  strings:
    $key_e250 = { b6 38 [2] c2 20 [2] 85 22 [2] c2 33 [2] 8c 3f [2] 80 35 [2] 97 3e [2] 8c 70 [2] b1 }

  condition:
    any of them
}