rule TTP_XOR_MULT_DOSStub_dd81 {
  strings:
    $key_dd81 = { 89 e9 [2] fd f1 [2] ba f3 [2] fd e2 [2] b3 ee [2] bf e4 [2] a8 ef [2] b3 a1 [2] 8e }

  condition:
    any of them
}