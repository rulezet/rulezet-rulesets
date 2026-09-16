rule TTP_XOR_MULT_DOSStub_eb07 {
  strings:
    $key_eb07 = { bf 6f [2] cb 77 [2] 8c 75 [2] cb 64 [2] 85 68 [2] 89 62 [2] 9e 69 [2] 85 27 [2] b8 }

  condition:
    any of them
}