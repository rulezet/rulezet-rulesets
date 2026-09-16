rule TTP_XOR_MULT_DOSStub_e9a1 {
  strings:
    $key_e9a1 = { bd c9 [2] c9 d1 [2] 8e d3 [2] c9 c2 [2] 87 ce [2] 8b c4 [2] 9c cf [2] 87 81 [2] ba }

  condition:
    any of them
}