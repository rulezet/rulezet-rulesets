rule TTP_XOR_MULT_DOSStub_1685 {
  strings:
    $key_1685 = { 42 ed [2] 36 f5 [2] 71 f7 [2] 36 e6 [2] 78 ea [2] 74 e0 [2] 63 eb [2] 78 a5 [2] 45 }

  condition:
    any of them
}