rule TTP_XOR_MULT_DOSStub_eba3 {
  strings:
    $key_eba3 = { bf cb [2] cb d3 [2] 8c d1 [2] cb c0 [2] 85 cc [2] 89 c6 [2] 9e cd [2] 85 83 [2] b8 }

  condition:
    any of them
}