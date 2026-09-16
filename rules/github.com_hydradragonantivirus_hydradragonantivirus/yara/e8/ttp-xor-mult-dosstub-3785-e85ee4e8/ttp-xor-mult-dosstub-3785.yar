rule TTP_XOR_MULT_DOSStub_3785 {
  strings:
    $key_3785 = { 63 ed [2] 17 f5 [2] 50 f7 [2] 17 e6 [2] 59 ea [2] 55 e0 [2] 42 eb [2] 59 a5 [2] 64 }

  condition:
    any of them
}