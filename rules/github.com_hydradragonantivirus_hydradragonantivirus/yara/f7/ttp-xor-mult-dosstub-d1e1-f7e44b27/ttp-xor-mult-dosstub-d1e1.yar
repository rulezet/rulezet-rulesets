rule TTP_XOR_MULT_DOSStub_d1e1 {
  strings:
    $key_d1e1 = { 85 89 [2] f1 91 [2] b6 93 [2] f1 82 [2] bf 8e [2] b3 84 [2] a4 8f [2] bf c1 [2] 82 }

  condition:
    any of them
}