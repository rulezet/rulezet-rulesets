rule TTP_XOR_MULT_DOSStub_eba9 {
  strings:
    $key_eba9 = { bf c1 [2] cb d9 [2] 8c db [2] cb ca [2] 85 c6 [2] 89 cc [2] 9e c7 [2] 85 89 [2] b8 }

  condition:
    any of them
}