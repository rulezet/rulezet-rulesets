rule TTP_XOR_MULT_DOSStub_e9c4 {
  strings:
    $key_e9c4 = { bd ac [2] c9 b4 [2] 8e b6 [2] c9 a7 [2] 87 ab [2] 8b a1 [2] 9c aa [2] 87 e4 [2] ba }

  condition:
    any of them
}