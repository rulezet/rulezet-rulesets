rule TTP_XOR_MULT_DOSStub_ebaa {
  strings:
    $key_ebaa = { bf c2 [2] cb da [2] 8c d8 [2] cb c9 [2] 85 c5 [2] 89 cf [2] 9e c4 [2] 85 8a [2] b8 }

  condition:
    any of them
}