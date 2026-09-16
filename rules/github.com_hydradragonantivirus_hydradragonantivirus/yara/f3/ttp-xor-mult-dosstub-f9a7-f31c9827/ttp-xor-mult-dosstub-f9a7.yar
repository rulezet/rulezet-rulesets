rule TTP_XOR_MULT_DOSStub_f9a7 {
  strings:
    $key_f9a7 = { ad cf [2] d9 d7 [2] 9e d5 [2] d9 c4 [2] 97 c8 [2] 9b c2 [2] 8c c9 [2] 97 87 [2] aa }

  condition:
    any of them
}