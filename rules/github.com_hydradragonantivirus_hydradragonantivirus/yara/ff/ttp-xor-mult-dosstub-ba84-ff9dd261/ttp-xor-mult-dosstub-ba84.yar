rule TTP_XOR_MULT_DOSStub_ba84 {
  strings:
    $key_ba84 = { ee ec [2] 9a f4 [2] dd f6 [2] 9a e7 [2] d4 eb [2] d8 e1 [2] cf ea [2] d4 a4 [2] e9 }

  condition:
    any of them
}