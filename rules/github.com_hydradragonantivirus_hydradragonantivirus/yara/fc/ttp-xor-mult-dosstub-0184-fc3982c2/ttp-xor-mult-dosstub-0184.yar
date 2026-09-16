rule TTP_XOR_MULT_DOSStub_0184 {
  strings:
    $key_0184 = { 55 ec [2] 21 f4 [2] 66 f6 [2] 21 e7 [2] 6f eb [2] 63 e1 [2] 74 ea [2] 6f a4 [2] 52 }

  condition:
    any of them
}