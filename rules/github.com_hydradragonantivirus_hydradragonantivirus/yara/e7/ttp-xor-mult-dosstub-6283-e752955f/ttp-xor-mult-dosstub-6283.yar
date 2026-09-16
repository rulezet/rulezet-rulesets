rule TTP_XOR_MULT_DOSStub_6283 {
  strings:
    $key_6283 = { 36 eb [2] 42 f3 [2] 05 f1 [2] 42 e0 [2] 0c ec [2] 00 e6 [2] 17 ed [2] 0c a3 [2] 31 }

  condition:
    any of them
}