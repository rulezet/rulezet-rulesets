rule TTP_XOR_MULT_DOSStub_dd88 {
  strings:
    $key_dd88 = { 89 e0 [2] fd f8 [2] ba fa [2] fd eb [2] b3 e7 [2] bf ed [2] a8 e6 [2] b3 a8 [2] 8e }

  condition:
    any of them
}