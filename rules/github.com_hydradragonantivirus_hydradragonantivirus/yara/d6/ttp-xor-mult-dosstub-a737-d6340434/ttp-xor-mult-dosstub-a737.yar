rule TTP_XOR_MULT_DOSStub_a737 {
  strings:
    $key_a737 = { f3 5f [2] 87 47 [2] c0 45 [2] 87 54 [2] c9 58 [2] c5 52 [2] d2 59 [2] c9 17 [2] f4 }

  condition:
    any of them
}