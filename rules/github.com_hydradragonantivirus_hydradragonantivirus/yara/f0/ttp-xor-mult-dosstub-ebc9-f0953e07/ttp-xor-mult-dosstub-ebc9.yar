rule TTP_XOR_MULT_DOSStub_ebc9 {
  strings:
    $key_ebc9 = { bf a1 [2] cb b9 [2] 8c bb [2] cb aa [2] 85 a6 [2] 89 ac [2] 9e a7 [2] 85 e9 [2] b8 }

  condition:
    any of them
}