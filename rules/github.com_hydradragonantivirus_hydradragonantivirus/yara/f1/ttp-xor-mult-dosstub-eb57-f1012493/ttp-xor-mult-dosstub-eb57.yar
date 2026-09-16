rule TTP_XOR_MULT_DOSStub_eb57 {
  strings:
    $key_eb57 = { bf 3f [2] cb 27 [2] 8c 25 [2] cb 34 [2] 85 38 [2] 89 32 [2] 9e 39 [2] 85 77 [2] b8 }

  condition:
    any of them
}