rule TTP_XOR_MULT_DOSStub_ebd4 {
  strings:
    $key_ebd4 = { bf bc [2] cb a4 [2] 8c a6 [2] cb b7 [2] 85 bb [2] 89 b1 [2] 9e ba [2] 85 f4 [2] b8 }

  condition:
    any of them
}