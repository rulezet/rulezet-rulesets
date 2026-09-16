rule TTP_XOR_MULT_DOSStub_f9a0 {
  strings:
    $key_f9a0 = { ad c8 [2] d9 d0 [2] 9e d2 [2] d9 c3 [2] 97 cf [2] 9b c5 [2] 8c ce [2] 97 80 [2] aa }

  condition:
    any of them
}