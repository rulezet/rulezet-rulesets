rule TTP_XOR_MULT_DOSStub_e9c7 {
  strings:
    $key_e9c7 = { bd af [2] c9 b7 [2] 8e b5 [2] c9 a4 [2] 87 a8 [2] 8b a2 [2] 9c a9 [2] 87 e7 [2] ba }

  condition:
    any of them
}