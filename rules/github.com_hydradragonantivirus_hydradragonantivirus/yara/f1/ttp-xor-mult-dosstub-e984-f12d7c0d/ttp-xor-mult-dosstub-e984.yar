rule TTP_XOR_MULT_DOSStub_e984 {
  strings:
    $key_e984 = { bd ec [2] c9 f4 [2] 8e f6 [2] c9 e7 [2] 87 eb [2] 8b e1 [2] 9c ea [2] 87 a4 [2] ba }

  condition:
    any of them
}