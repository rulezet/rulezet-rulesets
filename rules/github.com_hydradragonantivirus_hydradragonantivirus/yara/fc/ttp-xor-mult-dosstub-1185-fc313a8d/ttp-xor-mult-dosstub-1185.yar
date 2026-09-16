rule TTP_XOR_MULT_DOSStub_1185 {
  strings:
    $key_1185 = { 45 ed [2] 31 f5 [2] 76 f7 [2] 31 e6 [2] 7f ea [2] 73 e0 [2] 64 eb [2] 7f a5 [2] 42 }

  condition:
    any of them
}