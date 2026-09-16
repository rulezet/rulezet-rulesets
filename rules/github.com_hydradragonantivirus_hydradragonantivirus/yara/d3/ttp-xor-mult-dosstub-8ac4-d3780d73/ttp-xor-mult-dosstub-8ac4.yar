rule TTP_XOR_MULT_DOSStub_8ac4 {
  strings:
    $key_8ac4 = { de ac [2] aa b4 [2] ed b6 [2] aa a7 [2] e4 ab [2] e8 a1 [2] ff aa [2] e4 e4 [2] d9 }

  condition:
    any of them
}