rule TTP_XOR_MULT_DOSStub_f5a7 {
  strings:
    $key_f5a7 = { a1 cf [2] d5 d7 [2] 92 d5 [2] d5 c4 [2] 9b c8 [2] 97 c2 [2] 80 c9 [2] 9b 87 [2] a6 }

  condition:
    any of them
}