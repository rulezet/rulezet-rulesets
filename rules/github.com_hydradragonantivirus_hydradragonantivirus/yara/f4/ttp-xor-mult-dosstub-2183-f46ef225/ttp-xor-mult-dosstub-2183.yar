rule TTP_XOR_MULT_DOSStub_2183 {
  strings:
    $key_2183 = { 75 eb [2] 01 f3 [2] 46 f1 [2] 01 e0 [2] 4f ec [2] 43 e6 [2] 54 ed [2] 4f a3 [2] 72 }

  condition:
    any of them
}