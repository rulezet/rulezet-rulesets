rule TTP_XOR_MULT_DOSStub_ebc2 {
  strings:
    $key_ebc2 = { bf aa [2] cb b2 [2] 8c b0 [2] cb a1 [2] 85 ad [2] 89 a7 [2] 9e ac [2] 85 e2 [2] b8 }

  condition:
    any of them
}