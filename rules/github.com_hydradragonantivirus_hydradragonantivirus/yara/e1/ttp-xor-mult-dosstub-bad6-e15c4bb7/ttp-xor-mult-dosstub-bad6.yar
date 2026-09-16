rule TTP_XOR_MULT_DOSStub_bad6 {
  strings:
    $key_bad6 = { ee be [2] 9a a6 [2] dd a4 [2] 9a b5 [2] d4 b9 [2] d8 b3 [2] cf b8 [2] d4 f6 [2] e9 }

  condition:
    any of them
}