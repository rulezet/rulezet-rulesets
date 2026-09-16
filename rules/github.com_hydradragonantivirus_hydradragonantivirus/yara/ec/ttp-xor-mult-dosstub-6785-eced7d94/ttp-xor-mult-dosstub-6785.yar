rule TTP_XOR_MULT_DOSStub_6785 {
  strings:
    $key_6785 = { 33 ed [2] 47 f5 [2] 00 f7 [2] 47 e6 [2] 09 ea [2] 05 e0 [2] 12 eb [2] 09 a5 [2] 34 }

  condition:
    any of them
}