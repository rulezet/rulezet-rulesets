rule TTP_XOR_MULT_DOSStub_d483 {
  strings:
    $key_d483 = { 80 eb [2] f4 f3 [2] b3 f1 [2] f4 e0 [2] ba ec [2] b6 e6 [2] a1 ed [2] ba a3 [2] 87 }

  condition:
    any of them
}