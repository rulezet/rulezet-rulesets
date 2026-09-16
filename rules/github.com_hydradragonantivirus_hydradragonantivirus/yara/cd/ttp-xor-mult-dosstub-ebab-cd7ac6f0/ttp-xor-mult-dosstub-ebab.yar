rule TTP_XOR_MULT_DOSStub_ebab {
  strings:
    $key_ebab = { bf c3 [2] cb db [2] 8c d9 [2] cb c8 [2] 85 c4 [2] 89 ce [2] 9e c5 [2] 85 8b [2] b8 }

  condition:
    any of them
}