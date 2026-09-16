rule TTP_XOR_MULT_DOSStub_e9a7 {
  strings:
    $key_e9a7 = { bd cf [2] c9 d7 [2] 8e d5 [2] c9 c4 [2] 87 c8 [2] 8b c2 [2] 9c c9 [2] 87 87 [2] ba }

  condition:
    any of them
}