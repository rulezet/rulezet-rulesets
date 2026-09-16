rule TTP_XOR_MULT_DOSStub_d1e7 {
  strings:
    $key_d1e7 = { 85 8f [2] f1 97 [2] b6 95 [2] f1 84 [2] bf 88 [2] b3 82 [2] a4 89 [2] bf c7 [2] 82 }

  condition:
    any of them
}