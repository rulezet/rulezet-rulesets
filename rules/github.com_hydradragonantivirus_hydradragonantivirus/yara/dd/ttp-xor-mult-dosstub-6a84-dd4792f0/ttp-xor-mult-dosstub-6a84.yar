rule TTP_XOR_MULT_DOSStub_6a84 {
  strings:
    $key_6a84 = { 3e ec [2] 4a f4 [2] 0d f6 [2] 4a e7 [2] 04 eb [2] 08 e1 [2] 1f ea [2] 04 a4 [2] 39 }

  condition:
    any of them
}