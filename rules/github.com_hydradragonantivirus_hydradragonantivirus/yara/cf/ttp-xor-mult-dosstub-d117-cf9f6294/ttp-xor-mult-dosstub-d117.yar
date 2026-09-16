rule TTP_XOR_MULT_DOSStub_d117 {
  strings:
    $key_d117 = { 85 7f [2] f1 67 [2] b6 65 [2] f1 74 [2] bf 78 [2] b3 72 [2] a4 79 [2] bf 37 [2] 82 }

  condition:
    any of them
}