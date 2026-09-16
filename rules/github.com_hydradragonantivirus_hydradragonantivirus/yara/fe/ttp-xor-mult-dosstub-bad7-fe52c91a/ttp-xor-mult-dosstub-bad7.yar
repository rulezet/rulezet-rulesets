rule TTP_XOR_MULT_DOSStub_bad7 {
  strings:
    $key_bad7 = { ee bf [2] 9a a7 [2] dd a5 [2] 9a b4 [2] d4 b8 [2] d8 b2 [2] cf b9 [2] d4 f7 [2] e9 }

  condition:
    any of them
}