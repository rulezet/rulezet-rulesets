rule TTP_XOR_MULT_DOSStub_ca88 {
  strings:
    $key_ca88 = { 9e e0 [2] ea f8 [2] ad fa [2] ea eb [2] a4 e7 [2] a8 ed [2] bf e6 [2] a4 a8 [2] 99 }

  condition:
    any of them
}