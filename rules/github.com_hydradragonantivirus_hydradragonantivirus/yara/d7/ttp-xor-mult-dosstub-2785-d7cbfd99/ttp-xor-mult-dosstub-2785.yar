rule TTP_XOR_MULT_DOSStub_2785 {
  strings:
    $key_2785 = { 73 ed [2] 07 f5 [2] 40 f7 [2] 07 e6 [2] 49 ea [2] 45 e0 [2] 52 eb [2] 49 a5 [2] 74 }

  condition:
    any of them
}