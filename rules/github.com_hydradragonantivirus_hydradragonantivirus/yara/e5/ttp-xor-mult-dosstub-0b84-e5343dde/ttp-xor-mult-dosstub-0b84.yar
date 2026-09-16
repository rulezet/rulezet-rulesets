rule TTP_XOR_MULT_DOSStub_0b84 {
  strings:
    $key_0b84 = { 5f ec [2] 2b f4 [2] 6c f6 [2] 2b e7 [2] 65 eb [2] 69 e1 [2] 7e ea [2] 65 a4 [2] 58 }

  condition:
    any of them
}