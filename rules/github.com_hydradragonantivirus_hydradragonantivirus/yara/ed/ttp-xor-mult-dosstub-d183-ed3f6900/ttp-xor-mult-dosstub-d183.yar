rule TTP_XOR_MULT_DOSStub_d183 {
  strings:
    $key_d183 = { 85 eb [2] f1 f3 [2] b6 f1 [2] f1 e0 [2] bf ec [2] b3 e6 [2] a4 ed [2] bf a3 [2] 82 }

  condition:
    any of them
}