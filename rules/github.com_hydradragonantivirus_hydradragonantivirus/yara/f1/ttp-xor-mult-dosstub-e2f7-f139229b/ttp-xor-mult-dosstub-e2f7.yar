rule TTP_XOR_MULT_DOSStub_e2f7 {
  strings:
    $key_e2f7 = { b6 9f [2] c2 87 [2] 85 85 [2] c2 94 [2] 8c 98 [2] 80 92 [2] 97 99 [2] 8c d7 [2] b1 }

  condition:
    any of them
}