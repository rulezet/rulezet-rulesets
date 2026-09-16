rule TTP_XOR_MULT_DOSStub_fcc1 {
  strings:
    $key_fcc1 = { a8 a9 [2] dc b1 [2] 9b b3 [2] dc a2 [2] 92 ae [2] 9e a4 [2] 89 af [2] 92 e1 [2] af }

  condition:
    any of them
}