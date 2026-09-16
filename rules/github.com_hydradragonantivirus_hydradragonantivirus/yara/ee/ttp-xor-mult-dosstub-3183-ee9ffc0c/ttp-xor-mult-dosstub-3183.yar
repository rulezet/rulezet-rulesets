rule TTP_XOR_MULT_DOSStub_3183 {
  strings:
    $key_3183 = { 65 eb [2] 11 f3 [2] 56 f1 [2] 11 e0 [2] 5f ec [2] 53 e6 [2] 44 ed [2] 5f a3 [2] 62 }

  condition:
    any of them
}