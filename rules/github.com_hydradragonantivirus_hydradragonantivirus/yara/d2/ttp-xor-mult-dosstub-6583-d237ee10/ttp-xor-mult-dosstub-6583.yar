rule TTP_XOR_MULT_DOSStub_6583 {
  strings:
    $key_6583 = { 31 eb [2] 45 f3 [2] 02 f1 [2] 45 e0 [2] 0b ec [2] 07 e6 [2] 10 ed [2] 0b a3 [2] 36 }

  condition:
    any of them
}