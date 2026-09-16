rule TTP_XOR_MULT_DOSStub_9487 {
  strings:
    $key_9487 = { c0 ef [2] b4 f7 [2] f3 f5 [2] b4 e4 [2] fa e8 [2] f6 e2 [2] e1 e9 [2] fa a7 [2] c7 }

  condition:
    any of them
}