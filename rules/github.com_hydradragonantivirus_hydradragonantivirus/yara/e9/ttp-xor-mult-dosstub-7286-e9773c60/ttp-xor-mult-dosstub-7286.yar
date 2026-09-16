rule TTP_XOR_MULT_DOSStub_7286 {
  strings:
    $key_7286 = { 26 ee [2] 52 f6 [2] 15 f4 [2] 52 e5 [2] 1c e9 [2] 10 e3 [2] 07 e8 [2] 1c a6 [2] 21 }

  condition:
    any of them
}