rule TTP_XOR_MULT_DOSStub_d137 {
  strings:
    $key_d137 = { 85 5f [2] f1 47 [2] b6 45 [2] f1 54 [2] bf 58 [2] b3 52 [2] a4 59 [2] bf 17 [2] 82 }

  condition:
    any of them
}