rule TTP_XOR_MULT_DOSStub_eb97 {
  strings:
    $key_eb97 = { bf ff [2] cb e7 [2] 8c e5 [2] cb f4 [2] 85 f8 [2] 89 f2 [2] 9e f9 [2] 85 b7 [2] b8 }

  condition:
    any of them
}