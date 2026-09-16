rule TTP_XOR_MULT_DOSStub_ca82 {
  strings:
    $key_ca82 = { 9e ea [2] ea f2 [2] ad f0 [2] ea e1 [2] a4 ed [2] a8 e7 [2] bf ec [2] a4 a2 [2] 99 }

  condition:
    any of them
}